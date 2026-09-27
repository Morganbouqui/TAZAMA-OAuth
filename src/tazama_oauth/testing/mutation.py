from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode
from tazama_oauth.testing.models import TestMutation,MutationKind

def mutate_url(url:str,m:TestMutation)->str:
    p=urlsplit(url); pairs=parse_qsl(p.query,keep_blank_values=True); out=[]
    if m.mutation is MutationKind.REMOVE_PARAMETER: out=[x for x in pairs if x[0]!=m.parameter]
    elif m.mutation is MutationKind.DUPLICATE_PARAMETER:
        out=list(pairs); current=next((v for k,v in pairs if k==m.parameter),''); out.append((m.parameter,m.replacement if m.replacement is not None else current))
    else:
        changed=False
        for k,v in pairs:
            if k==m.parameter:
                nv='' if m.mutation is MutationKind.EMPTY_PARAMETER else (m.replacement if m.replacement is not None else v)
                out.append((k,nv)); changed=True
            else: out.append((k,v))
        if not changed and m.mutation is not MutationKind.REMOVE_PARAMETER: out.append((m.parameter,m.replacement or ''))
    return urlunsplit((p.scheme,p.netloc,p.path,urlencode(out,doseq=True),p.fragment))
