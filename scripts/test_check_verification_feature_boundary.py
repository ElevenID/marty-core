import unittest

from check_verification_feature_boundary import check_repository


class VerificationFeatureBoundaryTests(unittest.TestCase):
    def test_repository_feature_boundary(self) -> None:
        check_repository()


if __name__ == "__main__":
    unittest.main()
