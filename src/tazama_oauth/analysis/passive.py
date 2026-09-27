from tazama_oauth.oauth.flow.mapper import observed_flows,supported_flows
def summarize(discovery:dict,metadata=None):
    reqs=discovery.get('authorization_requests',[]); flows=[]
    for r in reqs: flows.extend(observed_flows(r))
    if metadata: flows.extend(supported_flows(metadata))
    return {'oauth_detected':discovery.get('oauth_detected',False),'oidc_detected':bool(metadata and metadata.issuer),'issuer':metadata.issuer if metadata else None,'client_ids':sorted({r.client_id for r in reqs if r.client_id}),'callbacks':sorted({r.redirect_uri for r in reqs if r.redirect_uri}),'scopes':sorted({s for r in reqs for s in r.scopes}),'response_types':sorted({s for r in reqs for s in r.response_type}),'pkce_observed':any(r.code_challenge for r in reqs),'state_present':any(r.state is not None for r in reqs),'nonce_present':any(r.nonce is not None for r in reqs),'flows':[f.as_dict() for f in flows]}
