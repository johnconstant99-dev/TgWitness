/** Submitted credentials must never become the Discard baseline. No browser or network. */
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';

class Element extends EventTarget {
  constructor() {
    super();this.children=[];this.dataset={};this.value='';this.type='text';this.id='';
  }
  setAttribute() {}
  append(...items) { this.children.push(...items); }
  querySelectorAll() { return this.fields||[]; }
  querySelector() { return null; }
  getClientRects() { return [1]; }
  closest() { return null; }
}
globalThis.document=Object.assign(new Element(),{createElement:()=>new Element()});
globalThis.MutationObserver=class { observe() {} disconnect() {} };
const source=await readFile(new URL('../tgwitness/static/components/forms.js',import.meta.url),'utf8');
const {createFormControls}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));

const secret=new Element();secret.id='replica-secret';secret.type='password';
const form=new Element();form.id='replica-form';form.fields=[secret];
let session='1:default';
const controls=createFormControls({forms:[{form,setDirty:()=>{}}],roots:[],tr:text=>text,
  getSession:()=>session,toast:()=>{}});
const discard=()=>form.children[0].children[2].dispatchEvent(new Event('click'));

controls.loaded(form.id);
secret.value='submitted-A';
const saved=controls.capture(form.id);
secret.value='new-draft-B';
controls.clearSubmitted(saved,[secret.id]);
assert.equal(secret.value,'new-draft-B','A successful save must preserve a newer secret draft.');
controls.accepted(saved);
discard();
assert.equal(secret.value,'','Discard must clear the new draft, never restore the submitted secret.');

secret.value='submitted-C';
const unchanged=controls.capture(form.id);
controls.clearSubmitted(unchanged,[secret.id]);
assert.equal(secret.value,'','A submitted secret without later edits should clear immediately.');
controls.accepted(unchanged);
assert.equal(form.dataset.dirty,'false');

secret.value='  unnormalized  ';
const normalized=controls.capture(form.id);
secret.value='unnormalized'; // The server canonicalized a field with no newer local edit.
controls.accepted(normalized,false);
assert.equal(form.dataset.dirty,'false','Server normalization must become the clean baseline.');

secret.value='old-workspace-secret';
const stale=controls.capture(form.id);
session='2:another-workspace';controls.reset();
secret.value='current-workspace-draft';
controls.clearSubmitted(stale,[secret.id]);controls.accepted(stale);discard();
assert.equal(secret.value,'current-workspace-draft','Old replies cannot clear or restore another workspace draft.');
controls.destroy();
// Destination helpers have their own Add action and disappear when the service changes.
// They must not leave removed controls in the saved form's Discard baseline.
const destination=new Element();destination.id='alert-destinations';
const helper=new Element();helper.id='alert-builder-token';
helper.closest=selector=>selector==='.alerts-builder'?{}:null;
const alerts=new Element();alerts.id='alerts-form';alerts.fields=[destination,helper];
const alertControls=createFormControls({forms:[{form:alerts,setDirty:()=>{}}],roots:[],
  tr:text=>text,getSession:()=>session,toast:()=>{}});
alertControls.loaded(alerts.id);
helper.value='draft-destination-token';
assert.equal(alertControls.changed(alertControls.capture(alerts.id)),false);
const beforeRemoval=alertControls.capture(alerts.id);
alerts.fields=[destination];
assert.equal(alertControls.changed(beforeRemoval),false,'Removing helper fields must not dirty the saved form.');
destination.value='changed';
alerts.children[0].children[2].dispatchEvent(new Event('click'));
assert.equal(destination.value,'');
assert.equal(alerts.dataset.dirty,'false','Discard must leave no phantom helper changes.');
alertControls.destroy();
console.log('Write-only fields preserve newer drafts and discard to an empty baseline; stale replies are ignored.');
