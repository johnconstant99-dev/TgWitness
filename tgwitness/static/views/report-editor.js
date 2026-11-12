export function createReportEditor({root,tr,onEdit}) {
  const find=id=>root.querySelector('#'+id);
  const make=(tag,text='',cls='')=>{const el=document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el;};
  const icon=name=>{
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg'),use=document.createElementNS(svg.namespaceURI,'use');
    svg.classList.add('icon');svg.setAttribute('aria-hidden','true');use.setAttribute('href','#i-'+name);svg.append(use);return svg;
  };
  function fold(title,nodes,cls='') {
    const detail=make('details','','editor-details '+cls);detail.append(make('summary',tr(title)),...nodes);return detail;
  }
  const layout=root.querySelector('.studio-layout'),controls=root.querySelector('.studio-controls'),stage=root.querySelector('.studio-stage');
  const designs=root.querySelector('.report-designs'),templates=root.querySelector('.report-templates'),outline=root.querySelector('.report-outline');
  const [charts,documentFields]=controls.querySelectorAll(':scope > .studio-section');
  const notes=root.querySelector('.report-examination'),guidance=find('report-guidance'),parts=root.querySelector('.report-parts');
  const inspector=make('div','','editor-inspector'),tabs=make('div','','editor-tabs');
  tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label',tr('Design and contents'));
  const panels=new Map(),buttons=new Map();
  for(const [key,title,symbol] of [['cover','Cover','report'],['design','Report design','settings'],['charts','Charts','activity'],['contents','Report contents','journal']]) {
    const button=make('button'),panel=make('section','','editor-panel');button.type='button';button.id='report-edit-'+key;
    button.append(icon(symbol),make('span',tr(title)));button.dataset.editorTab=key;button.setAttribute('role','tab');
    panel.id='report-editor-'+key;panel.setAttribute('role','tabpanel');panel.setAttribute('aria-labelledby',button.id);
    button.setAttribute('aria-controls',panel.id);button.addEventListener('click',()=>select(key));
    button.addEventListener('keydown',event=>{
      if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
      event.preventDefault();const keys=[...panels.keys()],index=keys.indexOf(key),rtl=getComputedStyle(tabs).direction==='rtl';
      const next=event.key==='Home'?0:event.key==='End'?keys.length-1:(index+(event.key==='ArrowRight'!==rtl?1:-1)+keys.length)%keys.length;
      select(keys[next],true);
    });
    buttons.set(key,button);panels.set(key,panel);tabs.append(button);
  }
  inspector.append(tabs,...panels.values());layout.prepend(inspector);
  const cover=panels.get('cover');
  const title=find('report-case-title').parentElement,grid=documentFields.querySelector('.report-grid');
  cover.append(title,fold('Case details',[grid,find('report-notes').previousElementSibling,find('report-notes')]));
  const language=find('report-language').parentElement,theme=find('report-theme').parentElement;
  cover.append(language,theme);
  cover.append(fold('Contents preset',[templates]));
  panels.get('design').append(designs);
  panels.get('charts').append(charts);
  panels.get('contents').append(parts,notes,guidance);
  const partLimit=root.querySelector('.report-part-size');
  parts.append(fold('Technical details',[find('report-raw').closest('label'),find('report-heartbeats').closest('label'),partLimit]));
  const chartOptions=charts.querySelector('.report-grid'),chartHints=[...charts.querySelectorAll(':scope > p')];
  charts.append(fold('Details',[chartOptions,...chartHints]));
  for(const fieldset of [designs,templates,parts,charts])fieldset.querySelector(':scope > legend')?.classList.add('editor-field-legend');
  const designHelp=find('report-design-help');designs.append(fold('Details',[designHelp]));
  const presetHelp=templates.querySelector(':scope > p');if(presetHelp)templates.append(fold('Details',[presetHelp]));
  const fixed=root.querySelector('.studio-fixed');panels.get('contents').append(fold('Included in your report',[outline,fixed]));
  controls.remove();
  const chartShapes={
    'report-activity-chart':'<path d="M12 69H180" class="chart-example-axis"/><path d="M20 68V45h18v23m12 0V32h18v36m12 0V42h18v26m12 0V18h18v50m12 0V30h18v38" class="chart-example-fill"/><path d="M20 45h18v-9H20zm30-13h18v-8H50zm30 10h18V29H80zm30-24h18V9h-18zm30 12h18V18h-18z" class="chart-example-secondary"/>',
    'report-hourly-chart':Array.from({length:35},(_,i)=>'<rect x="'+(18+i%7*23)+'" y="'+(10+Math.floor(i/7)*14)+'" width="18" height="10" rx="2" opacity="'+(.12+(i*7%11)/12)+'" class="chart-example-fill"/>').join(''),
    'report-participant-chart':'<circle cx="24" cy="20" r="7" class="chart-example-secondary"/><circle cx="24" cy="42" r="7" class="chart-example-secondary"/><circle cx="24" cy="64" r="7" class="chart-example-secondary"/><path d="M42 14h125v12H42zm0 22h88v12H42zm0 22h51v12H42z" class="chart-example-fill"/>',
    'report-chat-chart':'<path d="M20 69V13m0 56h155" class="chart-example-axis"/><path d="M32 68V26h25v42m15 0V12h25v56m15 0V41h25v27m15 0V51h25v17" class="chart-example-fill"/>',
    'report-composition-chart':'<rect x="17" y="12" width="151" height="12" rx="3" class="chart-example-fill"/><rect x="17" y="34" width="99" height="12" rx="3" class="chart-example-secondary"/><rect x="17" y="56" width="60" height="12" rx="3" class="chart-example-tertiary"/>'
  };
  for(const [id,shape] of Object.entries(chartShapes)) {
    const input=find(id),label=input.closest('label'),picture=document.createElementNS('http://www.w3.org/2000/svg','svg');
    input.setAttribute('role','switch');input.setAttribute('aria-description',label.querySelector('small').textContent);
    picture.setAttribute('viewBox','0 0 192 82');picture.setAttribute('aria-hidden','true');
    picture.classList.add('chart-example');picture.innerHTML=shape;label.prepend(picture);
    label.dataset.chartChoice=id;input.addEventListener('change',()=>root.dispatchEvent(new CustomEvent('report:chart',{detail:{id,enabled:input.checked}})));
  }
  for(const input of parts.querySelectorAll('input[type=checkbox]'))input.setAttribute('role','switch');
  const profiles=find('report-profiles'),profileSummary=profiles.querySelector('summary'),profileLabel=profileSummary.textContent;
  profileSummary.replaceChildren(icon('layers'),make('span',profileLabel));profileSummary.setAttribute('aria-label',profileLabel);profileSummary.title=profileLabel;
  root.querySelector('.studio-heading').append(profiles);
  const closeProfiles=make('button',tr('Close'),'quiet');closeProfiles.type='button';profiles.append(closeProfiles);
  closeProfiles.addEventListener('click',()=>{profiles.open=false;profiles.querySelector('summary').focus();});
  profiles.addEventListener('keydown',event=>{if(event.key==='Escape'){profiles.open=false;profiles.querySelector('summary').focus();}});
  const stageInfo=fold('Details',[stage.querySelector(':scope > .hint:last-child')],'editor-preview-info');stage.append(stageInfo);
  const frame=find('report-preview-frame'),empty=find('report-preview-empty'),viewport=make('div','','editor-canvas');
  frame.before(viewport);viewport.append(frame,empty);
  const emptyCopy=empty.querySelector('p');if(emptyCopy)stageInfo.append(emptyCopy);
  const activity=make('span','','editor-preview-activity');activity.setAttribute('aria-hidden','true');stage.prepend(activity);
  const zoom=make('select','','editor-zoom');zoom.setAttribute('aria-label',tr('Zoom'));zoom.dataset.formIgnore='';
  zoom.append(new Option(tr('Automatic'),'auto'),new Option('100%','1'));stage.querySelector('.studio-preview-tabs').append(zoom);
  for(const type of ['input','change'])zoom.addEventListener(type,event=>{event.stopPropagation();resize();});
  const mobileModes=make('div','','editor-mobile-modes');mobileModes.setAttribute('role','group');mobileModes.setAttribute('aria-label',tr('Report studio'));
  for(const [key,label] of [['edit','Edit'],['preview','Preview']]){
    const button=make('button',tr(label),'secondary');button.type='button';button.dataset.editorMode=key;
    button.addEventListener('click',()=>mode(key));mobileModes.append(button);
  }
  layout.before(mobileModes);mode('edit');
  const finalLayout=make('div','','report-final-layout'),finalData=make('div','','editor-final-data');
  const finalPage=find('report-preview');finalPage.append(finalLayout);
  finalData.append(finalPage.querySelector('.report-preview-toolbar'),find('report-preview-status'),find('report-preview-result'));finalLayout.append(finalData);
  const overview=make('div','','editor-data-overview');overview.id='report-data-overview';find('report-data').querySelector('.report-section-heading').after(overview);
  const dataStatus=make('p','','hint editor-data-status');dataStatus.id='report-data-status';dataStatus.setAttribute('role','status');overview.after(dataStatus);
  const catalogToolbar=root.querySelector('.report-catalog-toolbar');
  catalogToolbar.append(fold('Details',[catalogToolbar.querySelector('.hint')]));
  const authorPanel=root.querySelector('.report-catalog-grid > div:nth-child(2)');
  const authors=fold('Authors',[...authorPanel.childNodes],'editor-authors');authorPanel.append(authors);authors.querySelector('h4')?.remove();
  const kinds=root.querySelector('.report-kind-options'),gap=find('report-selection-gaps').closest('label'),gapHelp=gap.nextElementSibling;
  const kindSlot=make('div');kinds.before(kindSlot);kindSlot.replaceWith(fold('Record types',[kinds]));
  find('report-data').append(fold('Missing message IDs',[gap,gapHelp]));
  let selected='cover';
  function select(key,focus=false){
    selected=panels.has(key)?key:'cover';
    for(const [name,panel] of panels){const active=name===selected;panel.hidden=!active;
      const button=buttons.get(name);button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;}
    if(focus)buttons.get(selected).focus();
    inspector.dataset.panel=selected;
  }
  function mode(value){layout.dataset.mobileMode=value;mobileModes.querySelectorAll('button').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.editorMode===value)));}
  const resize=()=>{
    const width=viewport.clientWidth,height=viewport.clientHeight;if(!width||!height)return;
    const automatic=zoom.value==='auto',pageWidth=automatic&&width<500?width:900,scale=automatic?Math.min(1,width/pageWidth):1;
    viewport.dataset.zoom=zoom.value;frame.style.width=pageWidth+'px';frame.style.height=Math.ceil((height-(automatic?0:18))/scale)+'px';frame.style.transform='scale('+scale+')';
  };
  frame.addEventListener('load',()=>{
    const document=frame.contentDocument;if(!document)return;
    const targets=[['.hero h1','report-case-title'],['.chart-activity figcaption','report-activity-chart'],
      ['.chart-heatmap figcaption','report-hourly-chart'],['.chart-participants figcaption','report-participant-chart'],
      ['.chart-chats figcaption','report-chat-chart'],['.chart-composition figcaption','report-composition-chart']];
    for(const [selector,id] of targets){
      const heading=document.querySelector(selector);if(!heading)continue;
      const button=document.createElement('button');button.type='button';button.setAttribute('aria-label',tr('Edit')+' · '+heading.textContent);
      button.title=tr('Edit');button.style.cssText='font:inherit;color:inherit;letter-spacing:inherit;line-height:inherit;text-align:inherit;padding:0;margin:0;border:0;border-radius:2px;background:none;cursor:pointer;width:100%';
      button.append(...heading.childNodes);heading.append(button);
      const edit=()=>{
        onEdit();
        const field=find(id),key=id.endsWith('-chart')?'charts':'cover';select(key);mode('edit');
        const panel=panels.get(key),target=field.closest('label')||field;
        panel.scrollTop+=target.getBoundingClientRect().top-panel.getBoundingClientRect().top-16;field.focus({preventScroll:true});
      };
      button.addEventListener('click',edit);
    }
  });
  new ResizeObserver(resize).observe(viewport);
  select('cover');
  return {
    select,
    reveal(field){
      for(const [key,panel] of panels)if(panel.contains(field)){select(key);mode('edit');}
    },
    step(index){
      root.dataset.reportStep=String(index);(index===2?finalLayout:layout).append(stage);
      if(index===1)mode('edit');resize();
    },
    reset(){select('cover');mode('edit');profiles.open=false;overview.replaceChildren();dataStatus.textContent='';},
    summary(data){
      overview.replaceChildren(...[['Selected records',data.counts?.selected_records],['Chats',data.counts?.chats],['Observed message senders',data.counts?.participants]].map(([label,value])=>{
        const card=make('div');card.append(make('strong',Number(value||0).toLocaleString()),make('span',tr(label)));return card;
      }));
    }
  };
}
