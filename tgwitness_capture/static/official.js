(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const english = Object.fromEntries([...document.querySelectorAll('[data-t]')].map(el => [el.dataset.t,el.textContent]));
  const ru = {language:'Язык',title:'Свидетель в официальном клиенте',intro:'Просмотр Telegram Web в отдельном браузере，с ограниченными действиями и подписанной записью．',token:'Токен управления рекордером',connect:'Подключиться',stop:'Немедленно остановить',limits:'Открытие клиента создаёт новую сессию Telegram，просмотр может отмечать сообщения прочитанными．Гарантии отсутствия ограничений аккаунта нет．Локальный рекордер не подтверждает независимость администратора среды．',plan:'1．Выберите способ наблюдения',mode:'Режим',passive:'Наблюдать без автоматических действий',paced:'Просматривать старые сообщения с ограниченным темпом',minutes:'Не более минут',minpause:'Минимальная пауза，секунды',maxpause:'Максимальная пауза，секунды',pixels:'Шаг прокрутки，пиксели',steps:'Не более шагов прокрутки',modes:'Оба режима сохраняют только наблюдаемое в клиенте，это не полная выгрузка аккаунта．Автоматический просмотр идёт последовательно，с переменными паузами，он не обещает незаметность автоматизации．',open:'Сохранить настройки и открыть официальный клиент',client:'2．Войдите и выберите чат',qr:'Отсканируйте официальный QR-код доверенным устройством Telegram．Вход не попадает в доказательную запись．Этот экран не принимает клики и нажатия клавиш．',password:'Пароль двухэтапной проверки Telegram',submitpassword:'Передать в официальную форму входа',refreshchats:'Прочитать видимый список чатов',chat:'Чат',selectchat:'Выбрать чат',chatlimit:'В списке только чаты，которые сейчас отображает официальный клиент．Выбор чата может отправить отметку прочтения．',observe:'3．Запишите процедуру',start:'Начать запись',older:'Прокрутить к старым',newer:'Прокрутить к новым',snapshot:'Сохранить снимок',finish:'Завершить и выйти из Telegram',pausehint:'На паузе ограничение действий остаётся включённым．Закрытие панели не останавливает процедуру，используйте паузу или завершение．',exporttitle:'4．Проверьте и скачайте',fingerprint:'Отпечаток ключа рекордера',boundary:'Граница подписанного журнала',proof:'Сохраните отпечаток ключа и контрольные точки независимо．Подписи обнаруживают изменения относительно этого ключа，видео и Cloudflare не удостоверяют содержимое сообщений．Пробелы записи и неподтверждённый выход отмечаются в пакете．',selection:'Сохранить ожидаемые настройки',checkpoint:'Скачать контрольную точку',export:'Скачать подписанный ZIP',events:'Последние события'};
  let lang = navigator.language.startsWith('ru') ? 'ru' : 'en', token = '', status = null, busy = false, refreshing = false, screenUrl = null, revision = 0;
  const access = new URLSearchParams(location.hash.slice(1)).get('access');
  if(access && /^[A-Za-z0-9_-]{43}$/.test(access)) {token=access; history.replaceState(null,'',location.pathname+location.search);}
  const text = (en,russian) => lang === 'ru' ? russian : en;
  function translate() {document.documentElement.lang=lang; $('language').value=lang; for(const el of document.querySelectorAll('[data-t]')) el.textContent=lang==='ru' ? ru[el.dataset.t] : english[el.dataset.t]; if(status) render(status);}
  $('language').addEventListener('change',()=>{lang=$('language').value; translate();}); translate();
  async function api(path,body) {
    const response=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
    if(!response.ok) {let detail=text('Operation refused','Действие отклонено'); try{const data=await response.json(); if(typeof data.detail==='string') detail=data.detail;}catch{} throw new Error(detail);}
    return response;
  }
  function render(data) {
    status=data; const o=data.official; if(!o) throw new Error('This recorder does not provide the official client');
    for(const button of document.querySelectorAll('#workspace button')) button.disabled=false;
    $('login').hidden=true; $('workspace').hidden=false;
    const names={created:text('Not started','Не запущен'),login:text('Login without recording','Вход без записи'),ready:text('Ready to record','Готов к записи'),observing:text('Recording','Идёт запись'),paused:text('Paused','Пауза'),stopped:text('Stopped','Остановлен'),finishing:text('Finishing','Завершение'),finished:text('Finished','Завершён')};
    $('badge').textContent=names[o.phase]+(o.reason?'：'+o.reason:''); $('badge').className='badge'+(data.settings.enabled?' active':o.reason?' error':'');
    $('selected').textContent=(o.selected_chat||text('No chat selected','Чат не выбран'))+' · '+o.steps+' '+text('steps','шагов');
    $('route').textContent=o.options.egress+' · '+o.options.proxy_server+' · '+(o.exit_ip||text('IP not checked yet','IP ещё не проверен'))+' · '+text('No direct fallback','Без прямого fallback');
    $('plan-section').hidden=o.phase!=='created'; $('client-section').hidden=['created','finished'].includes(o.phase);
    $('toggle').textContent=data.settings.enabled?text('Pause recording','Приостановить запись'):text('Start recording','Начать запись');
    $('toggle').disabled=!o.selected_chat||!['ready','paused','observing'].includes(o.phase); $('stop').disabled=['created','finished'].includes(o.phase);
    for(const id of ['older','newer','snapshot']) $(id).disabled=!data.settings.enabled;
    for(const id of ['chat-select','chats-refresh']) $(id).disabled=o.source_locked||!['login','ready','paused'].includes(o.phase);
    $('selection').disabled=!o.source;
    $('finish').disabled=['created','finished','finishing'].includes(o.phase); $('export').disabled=data.settings.enabled;
    $('video-help').textContent=data.video_available?text('Video available，closed segments enter the signed journal．','Видео доступно，закрытые сегменты входят в подписанный журнал．'):text('Video unavailable．A profile requiring video cannot start．','Видео недоступно．Профиль с обязательным видео не запустится．');
    $('fingerprint').textContent=data.fingerprint; $('boundary').textContent='#'+data.seq+' · '+data.head_hash;
    $('finish-result').textContent=o.phase==='finished'?(o.logout_confirmed?text('Telegram logout confirmed，browser context closed．','Выход из Telegram подтверждён，контекст браузера закрыт．'):text('Logout unconfirmed．Revoke this session from a trusted Telegram device．','Выход не подтверждён．Завершите эту сессию с доверенного устройства Telegram．')):'';
    if(busy) for(const button of document.querySelectorAll('#workspace button:not(#stop)')) button.disabled=true;
  }
  async function refresh() {
    if(!token||refreshing||busy) return; refreshing=true; const expected=revision;
    try {
      const data=await (await api('status')).json(); if(expected!==revision) return; render(data); const o=status.official;
      if(!['created','finished','finishing'].includes(o.phase)) {
        const login=await (await api('official/login')).json(); $('login-state').textContent=text('Client state：','Состояние клиента：')+login.state;
        $('password-form').hidden=login.state!=='password'||o.phase!=='login';
        const blob=await (await api('official/screen')).blob(); if(expected!==revision)return; if(screenUrl) URL.revokeObjectURL(screenUrl); screenUrl=URL.createObjectURL(blob); $('screen').src=screenUrl;
      }
      const events=await (await api('events')).json(); if(expected!==revision)return; $('events').replaceChildren();
      for(const event of events.slice(-12).reverse()){const row=document.createElement('li'); row.textContent='#'+event.seq+' · '+event.kind+' · '+event.observed_at; $('events').append(row);}
    } finally {refreshing=false;}
  }
  async function action(fn) {if(busy)return; busy=true; revision++; if(status)render(status); $('notice').textContent=''; try{await fn();}catch(e){$('notice').textContent=e.message;}finally{if(token){try{status=await(await api('status')).json();}catch(e){$('notice').textContent=e.message;}} busy=false; if(status)render(status); await refresh().catch(e=>{$('notice').textContent=e.message;});}}
  function download(blob,name){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);}
  $('login-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{token=$('token').value.trim();$('token').value='';render(await(await api('status')).json());const p=status.official.options; for(const [id,key] of Object.entries({mode:'mode',minutes:'session_minutes',minpause:'min_pause_seconds',maxpause:'max_pause_seconds',pixels:'scroll_pixels',steps:'max_steps'})) $(id).value=p[key];});});
  $('plan-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{await api('official/plan',{mode:$('mode').value,session_minutes:Number($('minutes').value),min_pause_seconds:Number($('minpause').value),max_pause_seconds:Number($('maxpause').value),scroll_pixels:Number($('pixels').value),max_steps:Number($('steps').value)});await api('official/open',{});});});
  $('password-form').addEventListener('submit',e=>{e.preventDefault();const password=$('password').value;$('password').value='';action(()=>api('official/password',{password}));});
  $('chats-refresh').addEventListener('click',()=>action(async()=>{const chats=await(await api('official/chats')).json();$('chats').replaceChildren(...chats.map(c=>new Option(c.title,c.handle)));}));
  $('chat-select').addEventListener('click',()=>action(()=>api('official/chat',{handle:$('chats').value})));
  $('toggle').addEventListener('click',()=>action(()=>api('settings',{enabled:!status.settings.enabled,screenshots:true,pages:true,database:false,video:status.video_available})));
  for(const direction of ['older','newer']) $(direction).addEventListener('click',()=>action(()=>api('official/scroll',{direction})));
  $('snapshot').addEventListener('click',()=>action(()=>api('snapshot',{})));
  $('finish').addEventListener('click',()=>action(()=>api('official/finish',{})));
  $('stop').addEventListener('click',()=>{api('official/stop',{}).then(()=>refresh()).catch(e=>{$('notice').textContent=e.message;});});
  $('selection').addEventListener('click',()=>download(new Blob([JSON.stringify({format:'tgwitness-official-selection-v1',options:status.official.options,source:status.official.source},null,2)],{type:'application/json'}),'official-settings.json'));
  $('checkpoint').addEventListener('click',()=>action(async()=>download(await(await api('checkpoint')).blob(),'official-checkpoint.json')));
  $('export').addEventListener('click',()=>action(async()=>download(await(await api('export',{})).blob(),'official-evidence.zip')));
  setInterval(()=>refresh().catch(e=>{$('notice').textContent=e.message;}),2500);
  if(token) refresh().catch(e=>{$('notice').textContent=e.message;});
})();
