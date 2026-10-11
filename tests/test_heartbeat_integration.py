"""Paired local repositories only; no sockets, model or webhook calls."""
import pytest
create_app = pytest.importorskip('ai_ops.app', reason='Paired service environment required').create_app
from fastapi.testclient import TestClient
from ai_ops_agent.agent import Worker
from test_agent import config


def test_real_agent_payload_to_real_service_with_request_and_response_loss(tmp_path,monkeypatch):
    admin={'Authorization':'Bearer '+'a'*40}
    client=TestClient(create_app(str(tmp_path/'service.sqlite'),'a'*40,'test'))
    token=client.post('/api/v1/assets',headers=admin,json={'id':'test','name':'Test','allowed_users':['nobody']}).json()['agent_token']
    cfg=config(tmp_path/'journal');cfg['agent_token']=token
    worker=Worker(cfg)
    def request(c,path,body,**kw):
        seq=body['heartbeat_telemetry']['attempt_seq']
        if seq==2:
            raise OSError('request never reached service')
        response=client.post(path,headers={'Authorization':'Bearer '+c['token']},json=body)
        assert response.status_code==200,response.text
        if seq==1:
            raise TimeoutError('service committed receipt, but response was lost')
        return response.json()
    monkeypatch.setattr('ai_ops_agent.agent.request',request)
    with pytest.raises(TimeoutError):worker.heartbeat()
    with pytest.raises(OSError):worker.heartbeat()
    worker.heartbeat();worker.heartbeat()
    hb=client.get('/api/v1/agents/test/status',headers=admin).json()['heartbeat']
    assert hb['attempt_count']==4 and hb['received_count']==3 and hb['not_received_count']==1
    assert [a['receipt'] for a in hb['attempts']]==['received','not_received_yet','received','received']
    assert [a['ack_status'] for a in hb['attempts']]==['unconfirmed','unconfirmed','acknowledged','unknown']
