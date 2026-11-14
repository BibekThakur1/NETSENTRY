from scripts.evaluate import evaluate

def test_labelled_evaluation_is_reproducible():
    report=evaluate()
    assert report['scenario_count']==13
    assert report['overall']['tp']==9
    assert report['overall']['fp']==0
    assert report['overall']['fn']==0
    assert report['per_rule']['dns_anomaly']['tp']==1
    assert report['per_rule']['outbound_transfer']['tp']==1
