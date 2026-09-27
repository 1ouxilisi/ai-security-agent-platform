#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""冒烟测试: security_training_deep"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== 功能冒烟测试 ===")
print()

# 1. Course system
from security_training_deep.course_system import (
    get_course_manager, get_content_manager, get_quality_manager, get_recommender
)
cm = get_course_manager()
c = cm.create_course({"title": "冒烟测试课程", "category": "web_security", "level": "intermediate", "type": "lab", "description": "冒烟测试用"})
print("1. 课程CRUD: 创建课程 {} - {}".format(c["id"], c["title"]))
c2 = cm.update_course(c["id"], {"title": "冒烟测试课程v2"})
print("   更新课程: {}".format(c2["title"]))
ch = get_content_manager().add_chapter(c["id"], "第一章 入门")
print("   添加章节: {} - {}".format(ch["id"], ch["title"]))
rev = get_quality_manager().add_review(c["id"], "test_user", 5, "非常好")
c_obj = cm.get_course(c["id"])
print("   添加评分: {}星, 课程均分={}".format(rev["rating"], c_obj["rating_avg"]))
recs = get_recommender().recommend_for_role("pentester")
print("   推荐测试: {} 门推荐课程".format(len(recs)))

# 2. Lab environment
from security_training_deep.lab_environment import (
    get_lab_manager, get_range_env, get_lab_evaluator, get_lab_sandbox
)
lm = get_lab_manager()
lab = lm.create_lab({"title": "冒烟测试实验", "category": "web_pentest", "difficulty": "medium"})
print("2. 实验环境: 创建实验 {}".format(lab["id"]))
asg = lm.assign_lab(lab["id"], "test_user")
print("   分配实验: {}".format(asg["id"]))
lm.start_lab(asg["id"])
lm.submit_lab(asg["id"], "flag{smoke_test_success}")
result = get_lab_evaluator().auto_grade(asg["id"])
print("   自动评分: {}分 ({})".format(result["score"], result["grade"]))
re = get_range_env()
first_range_id = list(re.ranges.keys())[0]
r = re.start_range(first_range_id)
print("   启动靶场: {} @ {}".format(r["name"], r["ip"]))
sb = get_lab_sandbox().create_sandbox("test_user", lab["id"])
ex = get_lab_sandbox().execute_in_sandbox(sb["id"], "nmap -sV target")
print("   沙箱执行: success={}".format(ex["success"]))

# 3. Exam & certification
from security_training_deep.exam_certification import (
    get_question_bank, get_exam_manager, get_exam_executor, get_exam_grader,
    get_certificate_manager,
)
qb = get_question_bank()
q = qb.add_question({"question": "冒烟测试题", "type": "single_choice", "options": ["A", "B", "C"], "answer_index": 0})
print("3. 考试认证: 添加题目 {}".format(q["id"]))
em = get_exam_manager()
first_qid = list(qb.questions.keys())[0]
exam_obj = em.create_exam("冒烟考试", question_ids=[first_qid])
em.publish_exam(exam_obj["id"])
print("   创建考试: {} - {}".format(exam_obj["id"], exam_obj["title"]))
attempt = get_exam_executor().start_exam(exam_obj["id"], "test_user")
get_exam_executor().submit_answer(attempt["id"], first_qid, 0)
get_exam_executor().submit_exam(attempt["id"])
grade = get_exam_grader().grade_exam(attempt["id"])
status = "通过" if grade["passed"] else "未通过"
print("   考试评分: {}分, {}".format(grade["percentage"], status))
cert = get_certificate_manager().generate_certificate("test_user", "冒烟认证", "associate", grade["percentage"])
print("   生成证书: {}".format(cert["cert_number"]))
verify = get_certificate_manager().verify_certificate(cert["cert_number"])
print("   验证证书: valid={}".format(verify["valid"]))

# 4. Competency
from security_training_deep.competency_assessment import get_assessor, get_gap_analyzer, get_badge
assessor = get_assessor()
assessor.self_assess("test_user", {"web_hacking": 2, "network_defense": 3, "incident_response": 1, "threat_hunting": 2})
print("4. 能力评估: 自评完成")
gap = get_gap_analyzer().analyze_gap("test_user", "security_analyst")
print("   差距分析: {}".format(gap["summary"]))
badge = get_badge().award_badge("test_user", "web_hacking", 3)
print("   颁发徽章: {} {}".format(badge["skill_name"], badge["level_name"]))

# 5. Enterprise
from security_training_deep.enterprise_training import (
    get_training_execution, get_training_statistics, get_training_compliance,
)
te = get_training_execution()
sess = te.create_session("冒烟培训课", "张讲师", "2026-09-15")
reg = te.enroll(sess["id"], "test_user", "技术部")
te.check_in(reg["id"])
stats = get_training_statistics().completion_stats()
print("5. 企业培训: 培训完成率={}%".format(stats["completion_pct"]))
comp = get_training_compliance()
cr = comp.run_compliance_check("iso27001", 85, 100)
print("   合规检查: {} 覆盖率={}% compliant={}".format(cr["framework"], cr["coverage_pct"], cr["compliant"]))

# 6. Awareness
from security_training_deep.security_awareness import (
    get_phishing_simulation, get_awareness_metrics,
)
ph = get_phishing_simulation()
camp = ph.create_campaign("冒烟钓鱼演练", ["user1", "user2", "user3", "user4", "user5"])
ph.simulate_click(camp["id"], "user1")
ph.simulate_click(camp["id"], "user2")
ph.simulate_report(camp["id"], "user3")
results = ph.campaign_results(camp["id"])
print("6. 安全意识: 钓鱼演练 点击率={}% 报告率={}% 风险={}".format(
    results["click_rate_pct"], results["report_rate_pct"], results["risk_level"]))
metrics = get_awareness_metrics().awareness_score()
print("   意识评分: {} ({})".format(metrics["score"], metrics["level"]))

# 7. Dashboard
from security_training_deep.training_dashboard import get_training_dashboard
dash = get_training_dashboard()
ov = dash.overview()
print("7. 控制台: 课程={} 实验={} 考试={} 证书={}".format(
    ov["course_stats"]["total_courses"],
    ov["lab_stats"]["total_labs"],
    ov["exam_stats"]["total_exams"],
    ov["exam_stats"]["total_certificates"],
))

print()
print("=== 冒烟测试全部通过 ===")
