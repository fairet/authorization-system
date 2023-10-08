import hashlib
import sys


class GenerateHash:
    @staticmethod
    def generate_hashed(text):
        return hashlib.sha1(str.encode(text)).hexdigest()


def main():
    print(GenerateHash.generate_hashed(text=sys.argv[1]))


if __name__ == "__main__":
    if sys.argv[1] is None:
        print("[-] Please use 'python generate_hash_password.py STR(text)'")
        exit()

    main()
