"""Distro plyara adapter, also run as an isolated unprivileged subprocess.

The parser's lexer supplies source spans. Filtering never rebuilds rule bodies,
so conditions, strings, imports and upstream license comments retain their bytes.
Ubuntu yarac remains the authority for validity and dependency resolution.
"""
import fnmatch
import hashlib
import json
import re
import sys
import uuid


def spans(text):
    import plyara
    lexer = plyara.Plyara().lexer
    lexer.input(text)
    result, start, scope, name = [], None, None, None
    for token in lexer:
        if start is None:
            if token.type in ('PRIVATE', 'GLOBAL'):
                scope = token.lexpos if scope is None else scope
            elif token.type == 'RULE':
                start = token.lexpos if scope is None else scope
                name = None
            elif token.type not in ('COMMENT', 'MCOMMENT'):
                scope = None
        elif name is None and token.type == 'ID':
            name = token.value
        elif token.type == 'RBRACE':
            result.append((name, start, token.lexpos + 1))
            start, scope, name = None, None, None
    if start is not None:
        raise ValueError('Incomplete rule source')
    return result


def analyze(request):
    import plyara
    from plyara.utils import generate_hash
    sources, disabled = request['sources'], set(request.get('disabled', []))
    if not isinstance(sources, list) or len(sources) > 16:
        raise ValueError('Invalid source count')
    catalog, selected, summaries, identities = [], {}, [], set()
    total = 0
    for source in sources:
        source_id, text = source['id'], source['content']
        if not re.fullmatch('[a-z][a-z0-9_]{0,31}', source_id) or source_id in selected:
            raise ValueError('Invalid or duplicate source identifier')
        if not isinstance(text, str):
            raise ValueError('Invalid source text')
        total += len(text.encode())
        if total > 64 * 1024**2:
            raise ValueError('Rule sources exceed the size allowance')
        parser = plyara.Plyara()
        models = parser.parse_string(text)
        if parser.includes:
            raise ValueError('Includes must be resolved into an uploaded source; filesystem includes are forbidden')
        positions = spans(text)
        if len(models) != len(positions) or not models:
            raise ValueError('Parser did not account for all rules')
        metadata_names = {}
        for model in models:
            fields = {k:v for field in model.get('metadata',[]) for k,v in field.items()}
            try:
                metadata_id = str(uuid.UUID(str(fields.get('id'))))
                metadata_names.setdefault(metadata_id,set()).add(model['rule_name'])
            except (ValueError,AttributeError):
                pass
        names, removals, nodes = {}, [], []
        for model, (name, begin, end) in zip(models, positions):
            if name != model['rule_name']:
                raise ValueError('Parser and lexer disagree about rule boundaries')
            raw = text[begin:end]
            body_hash = hashlib.sha256(raw.encode()).hexdigest()
            # Metadata is excluded, but scope/import context is part of identity.
            logic_hash = generate_hash(model)
            context_hash = hashlib.sha256(json.dumps([logic_hash, sorted(model.get('scopes', [])),
                sorted(model.get('imports', []))], sort_keys=True).encode()).hexdigest()
            if name in names:
                if names[name]['context_hash'] != context_hash:
                    raise ValueError('Conflicting definitions of rule ' + name)
                removals.append((begin, end))
                names[name]['duplicate_definitions'] += 1
                continue
            metadata = {}
            for field in model.get('metadata', []):
                metadata.update(field)
            stable_id = name
            try:
                stable_id = str(uuid.UUID(str(metadata.get('id'))))
                if len(metadata_names[stable_id])>1:
                    # Some real Forge rules intentionally share an upstream ID.
                    # Keep each definition addressable instead of rejecting the
                    # whole valid package or silently merging different rules.
                    stable_id += ':' + name
            except (ValueError, AttributeError):
                pass
            rule_id = source_id + ':' + stable_id
            if rule_id in identities:
                raise ValueError('Conflicting catalog rule identifiers')
            identities.add(rule_id)
            node = dict(id=rule_id, name=name, source_id=source_id, namespace=source['namespace'],
                        tags=model.get('tags', []), scopes=model.get('scopes', []),
                        metadata=metadata, imports=model.get('imports', []),
                        sha256=body_hash, logic_hash=logic_hash, context_hash=context_hash,
                        enabled=rule_id not in disabled, dependencies=[],
                        duplicate_definitions=0, start_line=model['start_line'], stop_line=model['stop_line'])
            names[name] = node
            nodes.append((node, model, begin, end))
        has_globals = any('global' in n['scopes'] and n['enabled'] for n, _, _, _ in nodes)
        for node, model, begin, end in nodes:
            terms = model['condition_terms']
            dependencies = set()
            for index, term in enumerate(terms):
                if term in names:
                    if index + 1 < len(terms) and terms[index + 1] == '*':
                        dependencies.update(n['id'] for name, n in names.items() if fnmatch.fnmatchcase(name, term + '*'))
                    else:
                        dependencies.add(names[term]['id'])
                elif index + 1 < len(terms) and terms[index + 1] == '*' and re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', term):
                    dependencies.update(n['id'] for name, n in names.items() if fnmatch.fnmatchcase(name, term + '*'))
            node['dependencies'] = sorted(dependencies)
            node['dedup_safe'] = not dependencies and not has_globals and not node['scopes']
            if not node['enabled']:
                removals.append((begin, end))
            elif any(dep in disabled for dep in dependencies):
                raise ValueError('Enabled rule ' + node['name'] + ' depends on a disabled rule')
            catalog.append(node)
        # Keep comments outside removed bodies, including complete license blocks.
        filtered = text
        for begin, end in sorted(removals, reverse=True):
            filtered = filtered[:begin] + ('\n' * text[begin:end].count('\n')) + filtered[end:]
        selected[source_id] = filtered
        summaries.append(dict(id=source_id, rules=len(nodes), enabled=sum(n['enabled'] for n, _, _, _ in nodes),
                              imports=sorted(parser.imports), duplicates_removed=len(models)-len(nodes)))
        if len(catalog) > 50000:
            raise ValueError('Rule count exceeds the catalog allowance')
    groups = {}
    for node in catalog:
        if node['dedup_safe']:
            groups.setdefault(node['context_hash'], []).append(node['id'])
    for node in catalog:
        node['duplicate_rules'] = [rule_id for rule_id in groups.get(node['context_hash'], []) if rule_id != node['id']]
    return dict(catalog=catalog, selected=selected, sources=summaries,
                stale_overrides=sorted(disabled - identities))


if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(96 * 1024**2 + 1)
        if len(raw) > 96 * 1024**2:
            raise ValueError('Input exceeds the parser allowance')
        result = analyze(json.loads(raw))
        print(json.dumps(result, separators=(',', ':')))
    except Exception as exc:
        print(json.dumps({'error': str(exc)[:300]}))
        raise SystemExit(1)
