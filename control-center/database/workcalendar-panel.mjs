// Display-only metadata from readVpsBackupCatalog; no SQL or credential access.
const OWN_DATABASE={id:'database:workcalendar-postgres-workcalendar-app',externalId:'workcalendar-postgres-workcalendar-app',kind:'database',projectId:'workcalendar',name:'workcalendar_app',engine:'postgres'};
export function workcalendarDatabasePanel(native,projectId,{escapeHtml,controlIcon}){
 if(projectId!=='workcalendar'||!native)return '';
 const app=native.applications?.find(a=>a.id==='workcalendar');
 const db=app?.resources?.find(r=>r.kind==='database');
 if(!db||Object.keys(db).length!==Object.keys(OWN_DATABASE).length||Object.entries(OWN_DATABASE).some(([k,v])=>db[k]!==v))return '';
 return `<div class="ops-project-detail-panel" id="project-databases"><div class="ops-project-detail-panel-head"><h3>Database</h3><span class="ops-state good">1 collegato</span></div><div class="ops-project-database-list"><div class="ops-project-database-row" id="database-workcalendar-postgres-workcalendar-app"><div class="ops-project-database-main"><span class="ops-project-detail-item-icon">${controlIcon('databases')}</span><span><strong>Stexor Calendar</strong><small>${escapeHtml(db.name)} · PostgreSQL · utente dedicato workcalendar_app</small><small>Informazioni sul database in uso, gestito dall’applicazione.</small><small>Backup dedicato e verifica del ripristino nella sezione Backup.</small></span></div></div></div></div>`;
}
