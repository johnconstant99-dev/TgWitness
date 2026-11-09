export function topologyExample(){
  const at='2026-11-07T12:00:00Z',tg='149.154.160.0/20';
  const dcs={1:['149.154.175.53','Miami'],2:['149.154.167.51','Amsterdam'],3:['149.154.175.100','Miami'],4:['149.154.167.91','Amsterdam'],5:['149.154.171.5','Singapore']};
  const pool={listed:94,healthy:21,resting:8,probed_at:1794052800,lists_refreshed_at:1794049200,lists_blocked:false};
  const rows=[
    ['Primary workspace','mtproxy_auto',2,{host:'203.0.113.24',port:443},true,true],
    ['Case monitoring','mtproxy_auto',2,{host:'203.0.113.24',port:443},true,true],
    ['Archive research','mtproxy_auto',4,{host:'203.0.113.57',port:443},true,true],
    ['Public channels','warp',5,{host:'127.0.0.1',port:40121},true,true],
    ['Media collection','socks5',4,{host:'198.51.100.14',port:1080},true,true],
    ['History export','http',2,{host:'198.51.100.40',port:3128},true,true],
    ['Observer north','direct',1,null,true,true],
    ['Observer west','mtproxy_auto',5,{host:'203.0.113.91',port:443},true,true],
    ['Review account','mtproxy_auto',2,null,false,true],
    ['Independent review','socks5',4,{host:'198.51.100.14',port:1080},false,false],
  ];
  const accounts=rows.map(([label,kind,dc,gateway,connected,authorized],index)=>{
    const id=index?'000000000000000000000000000000'+String(index+1).padStart(2,'0'):'default';
    const warp=kind==='warp',direct=kind==='direct',endpoint={host:dcs[dc][0],port:443,telegram_network:tg};
    const calls=connected?[1842,1210,2316,904,3120,2648,611,1488][index]||0:0;
    return {id,label,group:null,state:connected?'connected':'disconnected',observing:connected,phase:connected?'running':'idle',run_id:'synthetic-topology-example',authorized,
      route:{kind:warp?'socks5':kind,managed:warp?'warp':null,gateway,source:kind==='mtproxy_auto'&&gateway?'Example list':null,latency_ms:kind==='mtproxy_auto'&&gateway?84+index*9:null,
        checked_at:kind==='mtproxy_auto'?1794052800:null,fallback:false,exposure:direct?'tunnel':'hide',tls:false,
        helper:warp?{mode:'warp',port:40121,running:true,paused:false}:null,check:warp?{telegram_connected:true,exit_ip:'198.51.100.77',country:'NL',warp:'on',checked_at:at}:null,
        pool:kind==='mtproxy_auto'?pool:null},
      outside:{enabled:index<4,route:index<4?'socks5':'none',gateway:index<4?{host:'198.51.100.14',port:1080}:null,problem:null},
      telegram:{dc:authorized?dc:null,endpoint:authorized?endpoint:null},
      socket:connected?{local:{host:'10.0.0.5',port:51300+index*7},peer:direct?endpoint:{...gateway,telegram_network:null}}:null,
      media:index===0?[{dc:4,connected:true,socket:{local:{host:'10.0.0.5',port:51388},peer:{host:'203.0.113.24',port:443,telegram_network:null}}}]:[],
      activity:{available:connected,since:at,calls,ok:Math.max(0,calls-3),errors:connected?1:0,flood_waits:0,
        methods:connected?[{method:'GetHistoryRequest',calls:Math.round(calls*.6),errors:0},{method:'GetDialogsRequest',calls:Math.round(calls*.1),errors:0}]:[],
        last_update_at:connected?at:null,last_heartbeat:connected?at:null},
      storage:{directory:'/var/lib/tgwitness/profiles/'+id,vault:'/var/lib/tgwitness/profiles/'+id+'/vault',key_mode:'local'},
      services:{timestamps:{enabled:true,endpoints:[{host:'freetsa.org',port:443},{host:'timestamp.sectigo.com',port:443}],interval_minutes:10,health:'ok'},
        calendars:{enabled:true,endpoints:[{host:'a.pool.opentimestamps.org',port:443}]},drand:{enabled:true},gateway_log:{enabled:false},devices:{enabled:false},
        replica:{enabled:index===0,endpoints:index===0?[{host:'s3.example.org',port:443}]:[],recipient_encryption:true,health:'ok'},
        storage:{enabled:false,backend:'local',endpoints:[]},alerts:{enabled:index===0,kinds:index===0?['ntfy']:[]},webhooks:{enabled:false,endpoints:[]},
        analysis:{enabled:false,endpoints:[]},proxy_lists:{enabled:kind==='mtproxy_auto'},proxy_checks:{enabled:kind==='mtproxy_auto'},operator_bot:{enabled:false},
        source_check:{enabled:index===0,checked_at:at,matches:true},witness:{enabled:index===0,tokens:index===0?1:0,last_poll:index===0?at:null,overdue:false},
        recorder_browser:{enabled:false,configured:false,endpoints:[]},recorder_ayugram:{enabled:false,configured:false,endpoints:[]},
        recorder_trusted:{enabled:index===0,configured:index===0,endpoints:index===0?[{host:'127.0.0.1',port:8793}]:[]}}};
  });
  const event=(id,kind,component,host,extra={})=>({id,at,kind,workspace:'default',component,purpose:'Synthetic example',destination:{host,port:443,telegram_network:null,loopback:false},outcome:'attempt',...extra});
  return {schema:'tgwitness-topology-v1',generated_at:at,demo:true,
    host:{kind:'server',place:'server',container:false,provider:'hetzner',tdx:false,hostname:'example-host',os:'Linux',machine:'x86_64',python:'3.12.7',version:'0.9.2',run_id:'synthetic-topology-example',started_at:at},
    ingress:{listener:{host:'127.0.0.1',port:8787},peer:'127.0.0.1',peer_trusted:false,via:'cloudflare',scheme:'https',forwarded_proto:'https',trusted_proxies:0,proxy_header:null,allowed_networks:0,
      token_source:'environment',published:{kind:'quick',host:'example.trycloudflare.com',tunnel_enabled:true},
      deployment:{provider:'hetzner',mode:'high-assurance',tunnel:'quick',panel_host:null,witness_host:null,ssh:'disabled'},
      sessions:[{admin:true,label:'Main administrator',address:'192.0.2.50',current:true,last_seen_at:at,requests:412}],grants:0},
    accounts,
    pool:{operator_catalog:false,feed_proxy:false,github_search:false,countries:true,github_status:{},lists:[{id:'example',label:'Example list',host:'raw.githubusercontent.com',enabled:true}],state:pool},
    policy:{private_destinations:false},
    telegram:{datacenters:Object.entries(dcs).map(([id,[address,city]])=>({id:Number(id),address,port:443,city,network:tg})),
      networks:['91.105.192.0/23','91.108.4.0/22','91.108.8.0/22','91.108.12.0/22','91.108.16.0/22','91.108.20.0/22','91.108.56.0/22','95.161.64.0/20','149.154.160.0/20','185.76.151.0/24',
        '2001:67c:4e8::/48','2001:b28:f23c::/47','2001:b28:f23f::/48','2a0a:f280::/32']},
    traffic:{available:true,started_at:at,total:1284,retained:9,capacity:2000,coverage:'python_process',events:[
      event(1276,'http_request','proxy_catalog','raw.githubusercontent.com',{method:'GET',outcome:'started',route:'socks5'}),
      event(1277,'http_result','proxy_catalog','raw.githubusercontent.com',{method:'GET',outcome:'response',status:200,duration_ms:184,parent:1276}),
      event(1278,'http_result','anchoring','freetsa.org',{method:'POST',outcome:'response',status:200,duration_ms:412}),
      event(1279,'http_result','anchoring','api.drand.sh',{method:'GET',outcome:'response',status:200,duration_ms:96}),
      event(1280,'http_result','replica','s3.example.org',{method:'PUT',outcome:'response',status:200,duration_ms:312}),
      event(1281,'http_result','alerts','ntfy.sh',{method:'POST',outcome:'response',status:200,duration_ms:140}),
      event(1282,'connect_attempt','telegram','203.0.113.24'),
      event(1283,'http_result','source_check','api.github.com',{method:'GET',outcome:'response',status:200,duration_ms:221}),
      event(1284,'http_result','anchoring','a.pool.opentimestamps.org',{method:'POST',outcome:'failed',error:'TimeoutError',duration_ms:15000}),
    ]}};
}
