/* Managed by clamshield */
(() => {
  'use strict';
  const map=JSON.parse(document.getElementById('cs-navigation-map').textContent);
  const pages=new Set(Object.values(map).flat()), remembered=new Map();
  const groupOf=page=>Object.keys(map).find(group=>map[group].includes(page));
  function stored(){try{return sessionStorage.getItem('clamshield-tab');}catch{return null;}}
  function select(group,page,writeHash=true){
    if(!Object.hasOwn(map,group))group='dashboard';
    if(!map[group].includes(page))page=remembered.get(group)||map[group][0];
    remembered.set(group,page);
    document.querySelectorAll('[data-page]').forEach(section=>section.hidden=section.dataset.page!==page);
    document.querySelectorAll('[data-subnav]').forEach(nav=>nav.hidden=nav.dataset.subnav!==group);
    document.querySelectorAll('[data-main-tab]').forEach(link=>{
      if(link.dataset.mainTab===group)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');
    });
    document.querySelectorAll('[data-tab]').forEach(link=>{
      if(link.dataset.tab===page)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');
    });
    try{sessionStorage.setItem('clamshield-tab',page);}catch{}
    if(writeHash)history.replaceState(null,'','#'+group+(page===map[group][0]?'':'/'+page));
    document.dispatchEvent(new CustomEvent('clamshield-tab-change',{detail:page}));
  }
  document.addEventListener('click',event=>{
    const link=event.target.closest('[data-main-tab],[data-tab]');if(!link||link.disabled)return;
    event.preventDefault();const page=link.dataset.tab;
    select(page?groupOf(page):link.dataset.mainTab,page);
    const target=document.getElementById(link.dataset.focusId||('cs-provider-'+link.dataset.focusProvider));
    if(target){for(let parent=target.parentElement;parent;parent=parent.parentElement)if(parent.tagName==='DETAILS')parent.open=true;target.scrollIntoView?.({block:'nearest'});target.focus();}
  });
  function fromHash(){
    const [group,page]=location.hash.slice(1).split('/');
    const legacy={results:'findings',exceptions:'exceptions',quarantine:'quarantine',history:'history'};
    if(Object.hasOwn(legacy,group)){select('review',map.review.includes(page)?page:legacy[group]);return;}
    if(page&&pages.has(page)&&groupOf(page)!==group){select(groupOf(page),page);return;}
    if(pages.has(group)){select(groupOf(group),group);return;}
    if(group){select(group,page,false);return;}
    const saved=stored();select(pages.has(saved)?groupOf(saved):'dashboard',saved,false);
  }
  window.addEventListener('hashchange',fromHash);fromHash();
})();
