/* Managed by clamshield: explicit measurement, bounded polling, no auto retry. */
(() => {
  'use strict';
  const root=document.getElementById('cs-signature-memory');if(!root)return;
  const start=document.getElementById('cs-memory-measure'),refresh=document.getElementById('cs-memory-refresh');
  const output=document.getElementById('cs-memory-status'),values=document.getElementById('cs-memory-values'),section=root.closest('[data-page]');
  let current=JSON.parse(root.dataset.measurement),busy=Boolean(current.running),checking=false,timer=null;
  const mib=bytes=>(Number(bytes)/1048576).toFixed(1)+' MiB';
  function render(){
    values.replaceChildren();const report=current.report;
    function paragraph(text){const p=document.createElement('p');p.textContent=text;values.append(p);return p;}
    if(current.error)paragraph(current.error).className='error';
    if(report){
      if(report.stale)paragraph('Measurements refer to different signature data or engine. Run a new measurement.').className='error';
      paragraph('Measured '+new Date(report.measured*1000).toISOString().slice(0,19).replace('T',' ')+' UTC · '+report.engine);
      const table=document.createElement('table'),head=document.createElement('thead'),body=document.createElement('tbody'),tr=document.createElement('tr');
      for(const title of ['Active configuration','Measured load peak / change']){const th=document.createElement('th');th.textContent=title;tr.append(th);}head.append(tr);table.append(head,body);
      function row(label,text){const tr=document.createElement('tr');for(const value of [label,text]){const td=document.createElement('td');td.textContent=value;tr.append(td);}body.append(tr);}
      row('Official and existing native signatures',mib(report.baseline.median_bytes));row('All active signatures',mib(report.all.median_bytes));
      for(const provider of report.providers||[])row(provider.label+' — observed change',(provider.delta_bytes>=0?'+':'')+mib(provider.delta_bytes));
      const scroll=document.createElement('div');scroll.className='scroll';scroll.append(table);values.append(scroll);
      paragraph('These are temporary process load peaks, not the native daemon’s steady RAM or its reload peak.');
    }else paragraph('No signature memory measurement recorded.');
    start.disabled=busy||!current.available;start.textContent=busy?'Measuring…':'Measure active signature memory';
  }
  function schedule(){clearTimeout(timer);timer=null;if(busy&&!section.hidden)timer=setTimeout(check,2000);}
  async function request(action){
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),20000);
    try{
      const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',signal:controller.signal,
        body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action})});
      const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Memory measurement request failed');return result;
    }finally{clearTimeout(timeout);}
  }
  async function check(){
    if(checking)return;checking=true;refresh.disabled=true;
    try{
      const result=await request('signature-memory-status');current=result.measurement;busy=Boolean(result.pending||current.running);
      const phase=result.latest?.result?.phase;
      output.textContent=busy?(result.latest?.status==='queued'?'Measurement queued.':phase==='preparing'?'Preparing active databases…':'Measuring fresh signature loads…'):
        result.latest?.status==='failed'?(result.latest.error||'Measurement failed; previous results retained.'):'Measurement status updated.';
      output.className='';render();schedule();
    }catch(error){output.textContent='Could not confirm measurement status: '+error.message;output.className='error';clearTimeout(timer);}
    finally{checking=false;refresh.disabled=false;}
  }
  start.addEventListener('click',async()=>{
    if(busy)return;busy=true;render();output.className='';output.textContent='Queuing memory measurement…';
    try{await request('signature-memory-measure');output.textContent='Measurement queued.';schedule();}
    catch(error){output.textContent='Could not confirm the measurement: '+error.message+'. Refresh status before trying again.';output.className='error';}
  });
  refresh.addEventListener('click',check);
  document.addEventListener('clamshield-tab-change',event=>{if(event.detail==='resources')check();else{clearTimeout(timer);timer=null;}});
  render();schedule();
})();
