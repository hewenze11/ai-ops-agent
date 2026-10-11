import copy
from concurrent.futures import ThreadPoolExecutor
import threading
import pytest
from ai_ops_agent.agent import Worker
from test_agent import config


def test_failed_send_increments_and_ack_loss_is_unconfirmed(tmp_path,monkeypatch):
    worker=Worker(config(tmp_path))
    bodies=[]
    def request(controller,path,body,**kwargs):
        bodies.append(copy.deepcopy(body))
        if len(bodies)==2:
            raise TimeoutError('response may have been lost')
        return {'accepted':True}
    monkeypatch.setattr('ai_ops_agent.agent.request',request)
    worker.heartbeat()
    with pytest.raises(TimeoutError):
        worker.heartbeat()
    worker.heartbeat()
    ts=[b['heartbeat_telemetry'] for b in bodies]
    assert [t['attempt_seq'] for t in ts]==[1,2,3]
    assert ts[2]['previous_results']==[{'attempt_seq':1,'outcome':'acknowledged'},{'attempt_seq':2,'outcome':'unconfirmed'}]
    assert ts[0]['session_id']==worker.instance_id and ts[0]['controller']=='default'
    assert 'token' not in str(ts) and '127.0.0.1' not in str(ts)


def test_two_controllers_do_not_share_sequence_or_failure(tmp_path,monkeypatch):
    worker=Worker(config(tmp_path,[{'name':'a','url':'https://a.example','token':'x'*40},
                                  {'name':'b','url':'https://b.example','token':'y'*40}]))
    calls=[]
    def request(c,path,body,**kwargs):
        calls.append(copy.deepcopy(body['heartbeat_telemetry']))
        if c['name']=='a':
            raise OSError('not delivered')
        return {'accepted':True}
    monkeypatch.setattr('ai_ops_agent.agent.request',request)
    with pytest.raises(OSError): worker.heartbeat(worker.controllers[0])
    worker.heartbeat(worker.controllers[1]); worker.heartbeat(worker.controllers[1])
    with pytest.raises(OSError): worker.heartbeat(worker.controllers[0])
    assert [(c['controller'],c['attempt_seq']) for c in calls]==[('a',1),('b',1),('b',2),('a',2)]
    assert calls[2]['previous_results'][0]['outcome']=='acknowledged'
    assert calls[3]['previous_results'][0]['outcome']=='unconfirmed'


def test_concurrent_attempts_unique_and_local_result_window_bounded(tmp_path,monkeypatch):
    worker=Worker(config(tmp_path)); seqs=[]; lock=threading.Lock()
    def request(c,path,body,**kwargs):
        t=body['heartbeat_telemetry']
        assert len(t['previous_results'])<=10
        assert all(t['attempt_seq']-10<=r['attempt_seq']<t['attempt_seq'] for r in t['previous_results'])
        with lock: seqs.append(t['attempt_seq'])
        return {'accepted':True}
    monkeypatch.setattr('ai_ops_agent.agent.request',request)
    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(lambda _:worker.heartbeat(),range(100)))
    assert sorted(seqs)==list(range(1,101))
    assert len(worker._heartbeat_state['default']['results'])<=10


def test_slow_controller_does_not_lock_other_controller(tmp_path,monkeypatch):
    worker=Worker(config(tmp_path,[{'name':'a','url':'https://a.example','token':'x'*40},
                                  {'name':'b','url':'https://b.example','token':'y'*40}]))
    started=threading.Event(); release=threading.Event()
    def request(c,*args,**kwargs):
        if c['name']=='a':
            started.set(); assert release.wait(5)
        return {'accepted':True}
    monkeypatch.setattr('ai_ops_agent.agent.request',request)
    with ThreadPoolExecutor(max_workers=2) as pool:
        slow=pool.submit(worker.heartbeat,worker.controllers[0]); assert started.wait(5)
        try:
            assert pool.submit(worker.heartbeat,worker.controllers[1]).result(2)['accepted']
        finally:
            release.set()
        slow.result(5)


def test_restart_session_and_max_sequence(tmp_path,monkeypatch):
    first=Worker(config(tmp_path)); second=Worker(config(tmp_path))
    assert first.instance_id!=second.instance_id
    calls=[]
    monkeypatch.setattr('ai_ops_agent.agent.request',lambda c,p,b,**kw:calls.append(b) or {'accepted':True})
    first.heartbeat(); second.heartbeat()
    assert all(b['heartbeat_telemetry']['attempt_seq']==1 for b in calls)
    first._heartbeat_state['default']['seq']=9007199254740991
    with pytest.raises(RuntimeError): first.heartbeat()
    assert len(calls)==2


def test_negative_response_is_not_acknowledged(tmp_path,monkeypatch):
    worker=Worker(config(tmp_path))
    monkeypatch.setattr('ai_ops_agent.agent.request',lambda *args,**kw:{'accepted':False})
    worker.heartbeat()
    assert worker._heartbeat_state['default']['results'][1]=='unconfirmed'


def test_old_strict_service_fallback_is_controller_local_and_counted(tmp_path,monkeypatch):
    import io, json, urllib.error
    worker=Worker(config(tmp_path,[{'name':'a','url':'https://a.example','token':'x'*40},
                                  {'name':'b','url':'https://b.example','token':'y'*40}]))
    calls=[]
    def request(c,path,body,**kw):
        calls.append((c['name'],body))
        if c['name']=='a' and 'heartbeat_telemetry' in body:
            data={'detail':[{'loc':['body','heartbeat_telemetry'],'type':'extra_forbidden'}]}
            raise urllib.error.HTTPError('https://test',422,'old',{},io.BytesIO(json.dumps(data).encode()))
        return {'accepted':True}
    monkeypatch.setattr('ai_ops_agent.agent.request',request)
    worker.heartbeat(worker.controllers[0]);worker.heartbeat(worker.controllers[0]);worker.heartbeat(worker.controllers[1])
    assert ['heartbeat_telemetry' in body for _,body in calls]==[True,False,False,True]
    assert worker._heartbeat_state['a']['seq']==3
    assert worker._heartbeat_state['a']['results']=={1:'unconfirmed',2:'acknowledged',3:'acknowledged'}
    assert calls[-1][1]['heartbeat_telemetry']['attempt_seq']==1


@pytest.mark.parametrize('code,detail',[(401,[]),(422,[{'loc':['body','heartbeat_telemetry','attempt_seq'],'type':'less_than_equal'}]),(422,'invalid')])
def test_no_downgrade_on_other_errors(tmp_path,monkeypatch,code,detail):
    import io, json, urllib.error
    worker=Worker(config(tmp_path));calls=[]
    def request(c,path,body,**kw):
        calls.append(body)
        raise urllib.error.HTTPError('https://test',code,'bad',{},io.BytesIO(json.dumps({'detail':detail}).encode()))
    monkeypatch.setattr('ai_ops_agent.agent.request',request)
    with pytest.raises(urllib.error.HTTPError):worker.heartbeat()
    assert len(calls)==1 and worker._heartbeat_state['default']['telemetry'] is True
