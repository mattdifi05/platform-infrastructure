import test from 'node:test';
import assert from 'node:assert/strict';
import {authorizeInfrastructureTurn,INFRASTRUCTURE_TOOLS} from '../ai/infrastructure-admin.mjs';

test('new infrastructure verbs need the current explicit target and reject negation',()=>{
 assert.equal(authorizeInfrastructureTurn('Ferma chrony.service','service_stop',{target:'chrony.service'}),true);
 assert.equal(authorizeInfrastructureTurn('Ferma rsyslog.service','service_stop',{target:'chrony.service'}),false);
 assert.equal(authorizeInfrastructureTurn('Non fermare chrony.service','service_stop',{target:'chrony.service'}),false);
 assert.equal(authorizeInfrastructureTurn('Installa rsyslog','package_install',{target:'rsyslog'}),true);
 assert.equal(authorizeInfrastructureTurn('Quali pacchetti dovrei installare?','package_install',{target:'rsyslog'}),false);
 assert.equal(authorizeInfrastructureTurn('Imposta SSH MaxAuthTries a 4','config_patch',{target:'sshd-hardening',maxAuthTries:4}),true);
 assert.equal(authorizeInfrastructureTurn('Imposta SSH MaxAuthTries a 5','config_patch',{target:'sshd-hardening',maxAuthTries:4}),false);
 assert.equal(authorizeInfrastructureTurn('Imposta backup timer Fri *-*-* 06:05:00 Europe/Rome','config_patch',{target:'vps-backup-timer',onCalendar:'Fri *-*-* 06:05:00 Europe/Rome'}),true);
 assert.equal(authorizeInfrastructureTurn('Imposta timer backup ogni venerdì alle 06:05','config_patch',{target:'vps-backup-timer',onCalendar:'Fri *-*-* 06:05:00 Europe/Rome'}),true);
 assert.equal(authorizeInfrastructureTurn('imposta timer backup ogni venerdì alle06:05','config_patch',{target:'vps-backup-timer',onCalendar:'Fri *-*-* 06:05:00 Europe/Rome'}),true);
 assert.equal(authorizeInfrastructureTurn('Set backup timer every Friday at 06:05','config_patch',{target:'vps-backup-timer',onCalendar:'Fri *-*-* 06:05:00 Europe/Rome'}),true);
 for(const message of ['Imposta timer backup ogni sabato alle 06:05','Imposta timer backup ogni venerdì alle 06:50','Imposta timer backup ogni venerdì alle 06:05 UTC','Imposta timer backup ogni venerdì alle 06:05 e sabato alle 07:05']){
  assert.equal(authorizeInfrastructureTurn(message,'config_patch',{target:'vps-backup-timer',onCalendar:'Fri *-*-* 06:05:00 Europe/Rome'}),false,message);
 }
});

test('new typed operations and read topics are exposed without a shell parameter',()=>{
 const read=INFRASTRUCTURE_TOOLS.find(row=>row.function.name==='readInfrastructure').function.parameters;
 const change=INFRASTRUCTURE_TOOLS.find(row=>row.function.name==='changeInfrastructure').function.parameters;
 for(const topic of ['timers','identity','config'])assert.ok(read.properties.topic.enum.includes(topic));
 for(const operation of ['service_stop','service_reload','service_enable','service_disable','package_install','config_patch'])assert.ok(change.properties.operation.enum.includes(operation));
 assert.equal(Object.hasOwn(change.properties,'command'),false);
 assert.deepEqual(change.properties.logLevel.enum,['INFO','VERBOSE']);
});
