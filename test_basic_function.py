import unittest

from basic_function import basic_function


class BasicFunctionTest(unittest.TestCase):
    def test_doubles_positive(self) -> None:
        self.assertEqual(basic_function(2), 4)

    def test_doubles_zero(self) -> None:
        self.assertEqual(basic_function(0), 0)

    def test_doubles_negative(self) -> None:
        self.assertEqual(basic_function(-3), -6)

    def test_rejects_bool(self) -> None:
        with self.assertRaises(TypeError):
            basic_function(True)

    def test_rejects_non_int(self) -> None:
        with self.assertRaises(TypeError):
            basic_function("2")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
