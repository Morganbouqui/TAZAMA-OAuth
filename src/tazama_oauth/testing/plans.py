from urllib.parse import urlsplit,parse_qs
from tazama_oauth.testing.models import TestMutation,MutationKind,TestPlan

def _mk(test,param,kind,target,baseline,replacement=None,prop='parameter binding'):
    return TestMutation(test,param,kind,target,prop,baseline,parse_qs(urlsplit(target).query).get(param,[None])[0],replacement)

def state_plan(target,baseline):
    return TestPlan('state',target,baseline,[_mk('state','state',MutationKind.REMOVE_PARAMETER,target,baseline),_mk('state','state',MutationKind.EMPTY_PARAMETER,target,baseline),_mk('state','state',MutationKind.REPLACE_PARAMETER,target,baseline,'tazama-mutated-state'),_mk('state','state',MutationKind.DUPLICATE_PARAMETER,target,baseline,'tazama-duplicate-state')])

def redirect_plan(target,baseline,alternate_callback=None):
    muts=[_mk('redirect-uri','redirect_uri',MutationKind.REPLACE_PARAMETER,target,baseline,'https://unauthorized.invalid/callback','redirect URI validation')]
    if alternate_callback:muts.append(_mk('redirect-uri','redirect_uri',MutationKind.ALTER_CALLBACK,target,baseline,alternate_callback,'redirect URI validation'))
    return TestPlan('redirect-uri',target,baseline,muts)

def pkce_plan(target,baseline):
    return TestPlan('pkce',target,baseline,[_mk('pkce','code_challenge',MutationKind.REMOVE_PARAMETER,target,baseline,prop='PKCE enforcement'),_mk('pkce','code_challenge',MutationKind.EMPTY_PARAMETER,target,baseline,prop='PKCE enforcement'),_mk('pkce','code_challenge',MutationKind.ALTER_PKCE,target,baseline,'malformed-challenge','PKCE enforcement'),_mk('pkce','code_challenge_method',MutationKind.REPLACE_PARAMETER,target,baseline,'plain','PKCE method enforcement')])
