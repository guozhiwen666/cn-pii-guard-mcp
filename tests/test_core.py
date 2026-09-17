"""核心算法与识别逻辑的回归测试。

运行：python -m unittest discover -s tests -v
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cnpii import detectors, validators  # noqa: E402


class TestValidators(unittest.TestCase):
    def test_cn_id_accepts_known_valid_number(self):
        ok, reason = validators.validate_cn_id("11010519491231002X")
        self.assertTrue(ok, reason)

    def test_cn_id_rejects_wrong_check_digit(self):
        ok, reason = validators.validate_cn_id("110105194912310021")
        self.assertFalse(ok)
        self.assertIn("校验位", reason)

    def test_cn_id_rejects_malformed(self):
        ok, _ = validators.validate_cn_id("1101051949123100")
        self.assertFalse(ok)

    def test_uscc_accepts_known_valid_code(self):
        ok, reason = validators.validate_uscc("91350100M000100Y43")
        self.assertTrue(ok, reason)

    def test_uscc_rejects_wrong_check_digit(self):
        ok, reason = validators.validate_uscc("91350100M000100Y44")
        self.assertFalse(ok)
        self.assertIn("校验位", reason)

    def test_uscc_rejects_forbidden_letter(self):
        # I / O / S / V / Z 不用于该编码体系
        ok, reason = validators.validate_uscc("91350100M000100YI3")
        self.assertFalse(ok)

    def test_bank_card_luhn(self):
        self.assertTrue(validators.validate_bank_card("4111111111111111")[0])
        self.assertFalse(validators.validate_bank_card("4111111111111112")[0])

    def test_bank_card_tolerates_separators(self):
        self.assertTrue(validators.validate_bank_card("4111 1111 1111 1111")[0])

    def test_mobile(self):
        self.assertTrue(validators.validate_cn_mobile("13800138000")[0])
        self.assertFalse(validators.validate_cn_mobile("12800138000")[0])
        self.assertFalse(validators.validate_cn_mobile("1380013800")[0])


class TestGenerators(unittest.TestCase):
    def test_generated_cn_id_passes_validation(self):
        for i in range(1, 6):
            value = validators.generate_cn_id(sequence=i)
            ok, reason = validators.validate_cn_id(value)
            self.assertTrue(ok, f"{value} -> {reason}")

    def test_generated_cn_id_gender_parity(self):
        male = validators.generate_cn_id(sequence=1, gender="male")
        female = validators.generate_cn_id(sequence=2, gender="female")
        self.assertEqual(int(male[16]), 1)
        self.assertEqual(int(female[16]) % 2, 0)

    def test_generated_uscc_passes_validation(self):
        for i in range(3):
            value = validators.generate_uscc(f"9135010{i}")
            ok, reason = validators.validate_uscc(value)
            self.assertTrue(ok, f"{value} -> {reason}")

    def test_generated_bank_card_passes_luhn(self):
        for length in (12, 16, 19):
            value = validators.generate_bank_card(length=length)
            self.assertEqual(len(value), length)
            self.assertTrue(validators.validate_bank_card(value)[0], value)


class TestDetectors(unittest.TestCase):
    SAMPLE = (
        "客户 张三 身份证 11010519491231002X，手机 13800138000，"
        "公司统一社会信用代码 91350100M000100Y43，"
        "打款卡号 4111111111111111，邮箱 zhangsan@example.com，"
        "来源 IP 192.168.1.100。"
    )

    def test_scan_finds_all_types(self):
        result = detectors.scan(self.SAMPLE)
        found = set(result["summary"].keys())
        self.assertTrue(
            {"id_card", "mobile", "uscc", "bank_card", "email", "ipv4"} <= found,
            f"未全部命中：{found}",
        )

    def test_scan_marks_validity(self):
        hits = detectors.scan(self.SAMPLE)["hits"]
        id_hit = next(h for h in hits if h["type"] == "id_card")
        self.assertTrue(id_hit["valid"])

    def test_id_card_wins_over_uscc_on_same_span(self):
        """18 位纯数字应判定为身份证，而不是统一社会信用代码。"""
        hits = detectors.scan("证件号 11010519491231002X")["hits"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["type"], "id_card")

    def test_boundary_assertion_blocks_embedded_digit_run(self):
        """超长纯数字串内部不应切出 18 位片段被误判。"""
        result = detectors.scan("流水号 991380013800099912345678")
        self.assertEqual(result["total"], 0, result["hits"])

    def test_checksum_filter_disambiguates_plain_18_digits(self):
        """恰好 18 位纯数字存在天然歧义：订单号与身份证号格式完全一致。

        仅靠正则无法区分，这正是本项目引入校验位判定的原因：
        默认报出但标记 valid=False，开启过滤后即可消除该类误报。
        """
        text = "订单号 991380013800099912"
        loose = detectors.scan(text, include_invalid=True)
        self.assertEqual(loose["total"], 1)
        self.assertFalse(loose["hits"][0]["valid"])

        strict = detectors.scan(text, include_invalid=False)
        self.assertEqual(strict["total"], 0)

    def test_mobile_embedded_in_order_number_is_not_matched(self):
        """订单号 991380013800099912 内嵌了合法手机号格式 13800138000。

        边界断言必须拦住它——这是脱敏工具最隐蔽的误报来源：
        数字串内部切片段，表面上"命中"了，实际把无关数据毁掉。
        """
        result = detectors.scan("订单号 991380013800099912", types=["mobile"])
        self.assertEqual(result["total"], 0, result["hits"])

        # 该串作为整体仍会被报为「形似身份证」，但校验位不过，可被过滤
        strict = detectors.scan("订单号 991380013800099912", include_invalid=False)
        self.assertEqual(strict["total"], 0)

    def test_mobile_masked_does_not_rewrite_embedded_lookalike(self):
        """脱敏时不能把订单号里的疑似片段一起改掉。"""
        text = "手机 13800138000，订单号 991380013800099912"
        out = detectors.mask(text, strategy="full", types=["mobile"])
        self.assertEqual(out["total"], 1)
        self.assertIn("991380013800099912", out["text"])
        self.assertNotIn("，手机 13800138000", out["text"])

    def test_type_filter(self):
        result = detectors.scan(self.SAMPLE, types=["mobile"])
        self.assertEqual(set(result["summary"].keys()), {"mobile"})

    def test_include_invalid_toggle(self):
        text = "疑似号码 110105194912310021"
        self.assertEqual(detectors.scan(text, include_invalid=True)["total"], 1)
        self.assertEqual(detectors.scan(text, include_invalid=False)["total"], 0)

    def test_mask_partial_does_not_leak_middle(self):
        out = detectors.mask(self.SAMPLE, strategy="partial")
        self.assertNotIn("11010519491231002X", out["text"])
        self.assertNotIn("13800138000", out["text"])
        self.assertIn("110****", out["text"])

    def test_mask_length_is_preserved(self):
        out = detectors.mask(self.SAMPLE, strategy="full")
        self.assertEqual(len(out["text"]), len(self.SAMPLE))

    def test_mask_hash_is_deterministic(self):
        a = detectors.mask("手机 13800138000", strategy="hash")["text"]
        b = detectors.mask("手机 13800138000", strategy="hash")["text"]
        self.assertEqual(a, b)

    def test_mask_keep_tail(self):
        out = detectors.mask("卡号 4111111111111111", strategy="keep_tail", types=["bank_card"])
        self.assertTrue(out["text"].endswith("1111"))
        self.assertNotIn("4111111111111111", out["text"])

    def test_mask_rejects_unknown_strategy(self):
        with self.assertRaises(ValueError):
            detectors.mask("13800138000", strategy="nope")


if __name__ == "__main__":
    unittest.main(verbosity=2)
