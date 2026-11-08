export function systemMapExample(){
  const at='2026-11-07T12:00:00Z';
  const kinds=['mtproxy_auto','socks5','mtproxy_auto','direct','socks5','http','mtproxy','mtproxy_auto','socks5','mtproxy_auto'];
  const accounts=kinds.map((kind,index)=>{
    const n=index+1,id=index?'000000000000000000000000000000'+String(n).padStart(4,'0'):'default';
    const connected=![4,8].includes(index),gateway=kind==='direct'?null:{host:kind==='socks5'?'127.0.0.1':'203.0.113.'+(20+n),port:kind==='socks5'?42000+n:443};
    const dc=[2,4,2,5,4,2,4,5,2,5][index],target={host:{2:'149.154.167.51',4:'149.154.167.91',5:'91.108.56.100'}[dc],port:443};
    return {id,label:['Primary workspace','Archive research','Case monitoring','Public channels','Review account','Media collection','History export','Observer north','Observer west','Independent review'][index],
      state:connected?'connected':'disconnected',observing:connected&&index!==6,phase:connected?'running':'idle',run_id:'synthetic-map-example',
      route:{kind,managed:kind==='socks5'?'warp':null,gateway,fallback:false,process_running:kind==='socks5',pool:kind==='mtproxy_auto'?{listed:94,healthy:21,resting:8}:null,proxy_checked_at:1794052800},
      policy:{exposure:kind==='direct'?'tunnel':'hide',outside_enabled:index<3,outside_route:index<3?'socks5':'none'},
      outside_gateway:index<3?{host:'127.0.0.1',port:42001+n}:null,
      socket:{local:connected?{host:'192.0.2.10',port:51000+n}:null,peer:connected?gateway||target:null},
      telegram:{dc,endpoint:target,endpoint_prefix:target.host+'/32'},
      activity:{available:connected,since:1794050000,calls:120+n*31,ok:118+n*31,errors:2,last_update_at:connected?at:null},
      check:{current:true,checked_at:1794052800,telegram_connected:connected,latency_ms:37+n},
      storage:{directory:'/example/data/'+id,vault_directory:'/example/data/'+id,key_mode:index===0?'external':'local',secrets_encrypted:true,journal_encrypted_by_app:false,media_encrypted_by_app:false},
      features:[
        {id:'timestamps',enabled:index<3,busy:false,health:'working',last_success:at,endpoints:[{host:'timestamp.example.org',port:443}]},
        {id:'replica',enabled:index<2,busy:false,health:'working',last_success:at,lag_records:0,recipient_encryption:false,retention_days:30,retention_mode:'GOVERNANCE',endpoints:[{host:'s3.example.org',port:443}]},
        {id:'storage',enabled:index===0,busy:false,backend:'s3',endpoints:[{host:'s3.example.org',port:443}]},
        {id:'witness',enabled:index===0,last_poll:at,overdue:false,endpoints:[]},
        {id:'drand',enabled:index<3,last_success:at,endpoints:[{host:'drand.cloudflare.com',port:443}]},
        {id:'gateway',enabled:index===0,last_success:at,endpoints:[{host:'api.cloudflare.com',port:443}]},
        {id:'devices',enabled:index<3,last_success:at,endpoints:[]},
        {id:'proxy_lists',enabled:kind==='mtproxy_auto',endpoints:[]},
        {id:'source_check',enabled:index===0,endpoints:[{host:'api.github.com',port:443}]},
        {id:'alerts',enabled:index===0,endpoints:[]},
        ...['operator_bot','webhooks','analysis','browser','ayugram','trusted'].map(id=>({id,enabled:false,configured:false,endpoints:[]})),
      ]};
  });
  return {schema:1,demo:true,generated_at:at,accounts,runtime:{os:'Linux',container:true,provider:null,place:'server',tdx_recorded:false,inventory_complete:false},
    ingress:{scheme:'http',listener:{host:'127.0.0.1',port:8787},cloudflare:'configured',authentication:'panel_session'},
    network_policy:{state:'unobserved',cidrs:[],packet_counters:null},
    traffic:{started_at:at,total:4,retained:4,capacity:2000,coverage:'synthetic_example',persisted:false,events:[
      {id:1,at,workspace:null,kind:'http_request',component:'proxy_catalog',purpose:'Download configured MTProxy list',destination:{host:'raw.githubusercontent.com',port:443},method:'GET',route:'socks5',outcome:'started'},
      {id:2,at,workspace:null,kind:'http_result',component:'proxy_catalog',purpose:'Download configured MTProxy list',destination:{host:'raw.githubusercontent.com',port:443},method:'GET',route:'socks5',outcome:'response',status:200,parent:1,duration_ms:184},
      {id:3,at,workspace:'default',kind:'http_result',component:'replica',purpose:'Maintain the encrypted off-site copy',destination:{host:'s3.example.org',port:443},method:'PUT',route:'socks5',outcome:'response',status:200,duration_ms:312},
      {id:4,at,workspace:'default',kind:'connect_attempt',component:'telegram',purpose:'Telegram transport',destination:{host:'203.0.113.21',port:443},outcome:'attempt'},
    ]}};
}
