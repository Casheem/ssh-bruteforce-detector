from analyzer import analyze

def write_log(tmp_path, lines):
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n")
    return str(p)

def fail(time, user, ip):
    return f"Oct 25 {time} host sshd[1]: Failed password for {user} from {ip} port 22 ssh2"

def accepted(time, user, ip):
    return f"Oct 25 {time} host sshd[1]: Accepted password for {user} from {ip} port 22 ssh2"

def test_burst_then_login_is_compromised(tmp_path):
    lines = [fail(f"03:00:{s:02d}", "root", "203.0.113.9") for s in range(6)]
    lines.append(accepted("03:00:30", "root", "203.0.113.9"))
    results, _ = analyze(write_log(tmp_path, lines), 2026, 5, 10)
    assert len(results) == 1
    assert results[0]["success_after_failures"] is True
    assert results[0]["peak_in_window"] == 6

def test_typo_user_is_not_compromised(tmp_path):
    lines = [
        fail("09:30:00", "khash", "192.0.2.10"),
        fail("09:30:10", "khash", "192.0.2.10"),
        accepted("09:31:00", "khash", "192.0.2.10"),
    ]
    results, _ = analyze(write_log(tmp_path, lines), 2026, 2, 10)
    assert len(results) == 1
    assert results[0]["success_after_failures"] is False

def test_slow_attacker_caught_by_total_count(tmp_path):
    lines = [fail(f"{h:02d}:00:00", "root", "198.51.100.23") for h in range(1, 7)]
    results, _ = analyze(write_log(tmp_path, lines), 2026, 5, 10)
    assert len(results) == 1
    assert results[0]["attempts"] == 6
    assert results[0]["peak_in_window"] == 1

def test_login_as_untargeted_user_is_not_compromised(tmp_path):
    lines = [fail(f"03:00:{s:02d}", "root", "203.0.113.9") for s in range(6)]
    lines.append(accepted("03:01:00", "alice", "203.0.113.9"))
    results, _ = analyze(write_log(tmp_path, lines), 2026, 5, 10)
    assert len(results) == 1
    assert results[0]["success_after_failures"] is False