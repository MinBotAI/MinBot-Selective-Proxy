import importlib.util
import io
import json
from pathlib import Path
import zipfile


def test_backup_update_preserves_accounts_settings_and_direct_rules():
    path = Path(__file__).parents[1] / "clients/karing/update_backup_rules.py"
    spec = importlib.util.spec_from_file_location("backup_update", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    routing = {"items": [{"groups": [
        {"name": "直连", "domain_suffix": ["feishu.cn"]},
        {"name": "MinBot 选择性代理", "domain_suffix": ["youtube.com"]},
    ]}], "rule_set_items": []}
    original = io.BytesIO()
    unchanged = {"karing_subscribe.json": b'{"account":"fixture"}',
                 "karing_setting.json": b'{"mode":"rule"}',
                 "karing_subscribe_use.json": b'{}'}
    with zipfile.ZipFile(original, "w") as z:
        for name, body in unchanged.items():
            z.writestr(name, body)
        z.writestr("karing_routing_group.json", json.dumps(routing))
    updated = module.update_backup(original.getvalue(), ["iyf.tv", "pipecdn.vip", "iyf.tv"])
    with zipfile.ZipFile(io.BytesIO(updated)) as z:
        assert set(z.namelist()) == set(unchanged) | {"karing_routing_group.json"}
        for name, body in unchanged.items():
            assert z.read(name) == body
        result = json.loads(z.read("karing_routing_group.json"))
    assert result["items"][0]["groups"][0] == routing["items"][0]["groups"][0]
    assert result["items"][0]["groups"][1]["domain_suffix"] == [
        "iyf.tv", "pipecdn.vip", "youtube.com"]
    assert module.update_backup(updated, ["iyf.tv"]) == updated
