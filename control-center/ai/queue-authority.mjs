// Ephemeral original-request authority. A restart intentionally makes queued work read-only.
export function createQueueAuthority(){
 const origins=new Map();
 const key=(scope,id)=>JSON.stringify([scope.subject,scope.machineId,scope.conversationId,id]);
 return {
  remember(scope,item){
   if(!item?.created||!item.id||!/^[a-f0-9]{64}$/.test(scope.sessionTokenHash||''))return;
   while(origins.size>=1000)origins.delete(origins.keys().next().value);
   origins.set(key(scope,item.id),{subject:scope.subject,role:scope.role,sessionTokenHash:scope.sessionTokenHash,at:Date.now()});
  },
  claim(scope,id){
   const k=key(scope,id),origin=origins.get(k);origins.delete(k);
   if(origin&&Date.now()-origin.at<86400000)return {subject:origin.subject,role:origin.role,sessionTokenHash:origin.sessionTokenHash};
   return {subject:scope.subject,role:scope.role,sessionTokenHash:null};
  },
 };
}
