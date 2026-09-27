from tazama_oauth.testing.plans import state_plan,pkce_plan,redirect_plan
def test_state_cases():
 p=state_plan('https://app/a?state=s','b'); assert {m.mutation.value for m in p.mutations}=={'REMOVE_PARAMETER','EMPTY_PARAMETER','REPLACE_PARAMETER','DUPLICATE_PARAMETER'}
def test_pkce_cases():
 p=pkce_plan('https://app/a?code_challenge=x&code_challenge_method=S256','b'); assert len(p.mutations)==4
def test_redirect_cases():
 p=redirect_plan('https://app/a?redirect_uri=https%3A%2F%2Fcb.test%2Fcb','b','https://alt.test/cb'); assert len(p.mutations)==2
