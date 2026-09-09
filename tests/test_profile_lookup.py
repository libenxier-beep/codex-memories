"""Personal lookup routing must be useful without exposing personal data."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from knowledge_router import route_knowledge
from agent_memory_system.hooks import CodexHookAdapter
from test_agent_memory_hooks import RecordingRuntime


class ProfileLookupTests(unittest.TestCase):
    def test_common_identity_questions_offer_a_private_read_handoff(self):
        for query in ("我的姓名是什么", "我叫什么名字", "我的专业是什么", "我在哪所大学", "What is my major?"):
            with self.subTest(query=query):
                try:
                    result = route_knowledge(query, root=Path("/nonexistent"))
                except ValueError:
                    self.fail("Personal lookup incorrectly reached the knowledge corpus")
                self.assertEqual(result["trace"]["stage"], "privacy_boundary")
                self.assertIn("USER.md", result.get("next_action", ""))
                self.assertIsNone(result.get("document"))

    def test_prompt_hook_guides_basic_and_implicit_profile_lookup(self):
        for query in ("我叫什么名字", "我的专业是什么", "我现在大二，毫无基础，我和你一起协作完成论文，应该发哪些期刊？", "帮我写署名", "根据我的专业给我实习建议"):
            with self.subTest(query=query):
                runtime = RecordingRuntime()
                result = CodexHookAdapter(runtime).handle({"hook_event_name": "UserPromptSubmit", "session_id": "profile-test", "cwd": "/tmp", "prompt": query})
                self.assertIsNotNone(result)
                context = result["hookSpecificOutput"]["additionalContext"]
                self.assertIn("USER.md", context)
                self.assertIn("before asking", context)
                self.assertLessEqual(len(context), 4000)

    def test_generic_work_does_not_trigger_personal_lookup(self):
        for query in ("修复数据库索引", "设计姓名和专业字段的数据库 schema", "总结这篇论文", "实现论文检索系统", "Inspect my namespace configuration", "Fix my major_version parser"):
            runtime = RecordingRuntime()
            result = CodexHookAdapter(runtime).handle({"hook_event_name": "UserPromptSubmit", "session_id": "profile-test", "cwd": "/tmp", "prompt": query})
            self.assertIsNone(result)

    def test_hint_does_not_echo_user_text_or_load_private_files(self):
        result = CodexHookAdapter(RecordingRuntime()).handle({"hook_event_name": "UserPromptSubmit", "session_id": "profile-test", "cwd": "/nonexistent", "prompt": "我的专业是什么 SECRET_TEST_MARKER"})
        self.assertIsNotNone(result)
        context = result["hookSpecificOutput"]["additionalContext"]
        self.assertNotIn("SECRET_TEST_MARKER", context)


if __name__ == "__main__":
    unittest.main()
