from pathlib import Path
import tempfile
import unittest

from clamshield.wordpress_uploads import cleanup_match


class UploadsPolicyTests(unittest.TestCase):
    def match(self,path,content,**options):
        with tempfile.TemporaryDirectory() as temp:
            copy=Path(temp)/'snapshot';copy.write_bytes(content)
            return cleanup_match(path,[{'path':''},{'path':'blog'}],{'uploads_php':True,'uploads_js':False,**options},copy)

    def test_binary_media_php_marker_bytes_are_not_script_policy(self):
        for extension in ('png','jpg','webp','avif','gif','pdf','txt'):
            with self.subTest(extension=extension):
                self.assertFalse(self.match('wp-content/uploads/photo.'+extension,b'\x00\xff<?=\x12<?php\x80'))

    def test_only_exact_inert_index_placeholder_is_exempt(self):
        for content in (b'<?php\n// Silence is golden.\n',b'<?php /* Silence is golden. */ ?>\n'):
            self.assertFalse(self.match('wp-content/uploads/smush/index.php',content))
        for content in (b'<?php // Silence is golden.\necho 1;',b'<?php /* Silence is golden. */ system("id");'):
            self.assertTrue(self.match('wp-content/uploads/smush/index.php',content))
        self.assertTrue(self.match('wp-content/uploads/other.php',b'<?php // Silence is golden.\n'))

    def test_script_and_optional_javascript_policies_remain_separate(self):
        self.assertTrue(self.match('blog/wp-content/uploads/a.PHP',b'<?php echo 1;'))
        self.assertFalse(self.match('blog/wp-content/uploads/a.php',b'<?php echo 1;',uploads_php=False))
        self.assertFalse(self.match('wp-content/uploads/a.js',b'console.log(1)'))
        self.assertTrue(self.match('wp-content/uploads/a.js',b'console.log(1)',uploads_js=True))

    def test_policy_does_not_cover_plugin_code_or_similar_directory_names(self):
        for path in ('wp-content/plugins/example/test.inc','wp-content/uploads-old/a.php','other/wp-content/uploads/a.php'):
            self.assertFalse(self.match(path,b'<?php echo 1;'))
