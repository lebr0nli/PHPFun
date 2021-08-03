# PHPFun: ([.^])

from argparse import ArgumentParser


class PHPFun:
    def __init__(self):
        # simple constant
        arr_str = "[].[]"  # "ArrayArray"

        # generate digits
        nums = {0: "[]^[]", 1: "[]^[[]]"}
        self.char_mapping = dict()
        self.char_mapping['A'] = f"({arr_str})[[]]"
        self.char_mapping['r'] = f"({arr_str})[[[]]]"
        nums[3] = f"{self.char_mapping['A']}^{self.char_mapping['r']}"  # "A" ^ "r"
        nums[2] = f"({arr_str})[[]]^({arr_str})[[[]]]^[[]]"  # "3" ^ [[]]
        self.char_mapping['y'] = f"(({nums[0]}).{arr_str})[({nums[1]}).({nums[0]})]"
        nums[8] = f"{self.char_mapping['A']}^{self.char_mapping['y']}"  # "A" ^ "y"
        nums[4] = f"{nums[8]}^[]^(({nums[1]}).({nums[2]}))"
        nums[5] = f"{nums[4]}^{nums[1]}"
        nums[6] = f"{nums[2]}^({nums[4]})"
        nums[7] = f"{nums[3]}^({nums[4]})"
        nums[9] = f"{nums[8]}^[[]]"

        self.nums = nums  # Note: 3 and 8 are string
        # using `Aray0123456789` & xor to generate printable ascii char
        self.char_mapping.update({
            '\t': f'({nums[1]}).[]^({arr_str})[[]]^({arr_str})[{nums[4]}]',
            '\n': f'({nums[2]}).[]^({arr_str})[[]]^({arr_str})[{nums[4]}]',
            '\x0b': f'({arr_str})[[[]]]^({arr_str})[{nums[4]}]',
            '\x0c': f'({nums[4]}).[]^({arr_str})[[]]^({arr_str})[{nums[4]}]',
            '\r': f'({nums[5]}).[]^({arr_str})[[]]^({arr_str})[{nums[4]}]',
            ' ': f'({arr_str})[[]]^({arr_str})[{nums[3]}]',
            '!': f'({nums[2]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]',
            '"': f'({nums[1]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]',
            '#': f'({nums[0]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]',
            '$': f'({nums[0]}).[]^({nums[4]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]',
            '%': f'({nums[1]}).[]^({nums[4]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]',
            '&': f'({nums[5]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]',
            "'": f'({nums[4]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]',
            '(': f'({nums[0]}).[]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            ')': f'({nums[1]}).[]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '*': f'({nums[2]}).[]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '+': f'({arr_str})[[]]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            ',': f'({nums[4]}).[]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '-': f'({nums[5]}).[]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '.': f'({nums[6]}).[]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '/': f'({nums[7]}).[]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '0': f'{nums[0]}',
            '1': f'{nums[1]}',
            '2': f'{nums[2]}',
            '3': f'{nums[3]}',
            '4': f'{nums[4]}',
            '5': f'{nums[5]}',
            '6': f'{nums[6]}',
            '7': f'{nums[7]}',
            '8': f'{nums[8]}',
            '9': f'{nums[9]}',
            ':': f'({nums[1]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[4]}]',
            ';': f'({nums[0]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[4]}]',
            '<': f'({nums[0]}).[]^({nums[4]}).[][[]]^({arr_str})[[]]^({arr_str})[{nums[4]}]',
            '=': f'({nums[1]}).[]^({nums[4]}).[]^({arr_str})[[]]^({arr_str})[{nums[4]}]',
            '>': f'({nums[5]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[4]}]',
            '?': f'({nums[4]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[4]}]',
            '@': f'({nums[2]}).[]^({arr_str})[[[]]]',
            # 'A': f"({arr_str})[[]]",
            'B': f'({nums[0]}).[]^({arr_str})[[[]]]',
            'C': f'({nums[1]}).[]^({arr_str})[[[]]]',
            'D': f'({nums[1]}).[]^({nums[4]}).[]^({arr_str})[[]]',
            'E': f'({nums[0]}).[]^({nums[4]}).[]^({arr_str})[[]]',
            'F': f'({nums[4]}).[]^({arr_str})[[[]]]',
            'G': f'({nums[5]}).[]^({arr_str})[[[]]]',
            'H': f'({nums[1]}).[]^({arr_str})[{nums[4]}]',
            'I': f'({nums[0]}).[]^({arr_str})[{nums[4]}]',
            'J': f'({arr_str})[[]]^({arr_str})[[[]]]^({arr_str})[{nums[4]}]',
            'K': f'({nums[2]}).[]^({arr_str})[{nums[4]}]',
            'L': f'({nums[5]}).[]^({arr_str})[{nums[4]}]',
            'M': f'({nums[4]}).[]^({arr_str})[{nums[4]}]',
            'N': f'({nums[7]}).[]^({arr_str})[{nums[4]}]',
            'O': f'({nums[6]}).[]^({arr_str})[{nums[4]}]',
            'P': f'({nums[1]}).[]^({arr_str})[{nums[3]}]',
            'Q': f'({nums[0]}).[]^({arr_str})[{nums[3]}]',
            'R': f'({arr_str})[[]]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]',
            'S': f'({nums[2]}).[]^({arr_str})[{nums[3]}]',
            'T': f'({nums[5]}).[]^({arr_str})[{nums[3]}]',
            'U': f'({nums[4]}).[]^({arr_str})[{nums[3]}]',
            'V': f'({nums[7]}).[]^({arr_str})[{nums[3]}]',
            'W': f'({nums[6]}).[]^({arr_str})[{nums[3]}]',
            'X': f'({nums[2]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'Y': f'({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'Z': f'({nums[0]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '[': f'({nums[1]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '\\': f'({nums[1]}).[]^({nums[4]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            ']': f'({nums[0]}).[]^({nums[4]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '^': f'({nums[4]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '_': f'({nums[5]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            '`': f'({nums[0]}).[]^({nums[1]}).[]^({arr_str})[{nums[3]}]',
            'a': f'({arr_str})[{nums[3]}]',
            'b': f'({nums[1]}).[]^({nums[2]}).[]^({arr_str})[{nums[3]}]',
            'c': f'({nums[0]}).[]^({nums[2]}).[]^({arr_str})[{nums[3]}]',
            'd': f'({nums[1]}).[]^({nums[4]}).[]^({arr_str})[{nums[3]}]',
            'e': f'({nums[0]}).[]^({nums[4]}).[]^({arr_str})[{nums[3]}]',
            'f': f'({nums[4]}).[]^({arr_str})[[]]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]',
            'g': f'({nums[2]}).[]^({nums[4]}).[]^({arr_str})[{nums[3]}]',
            'h': f'({nums[1]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'i': f'({nums[0]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'j': f'({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'k': f'({nums[2]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'l': f'({nums[5]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'm': f'({nums[4]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'n': f'({nums[0]}).[]^({nums[4]}).[]^({arr_str})[[[]]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'o': f'({nums[6]}).[]^({arr_str})[[]]^({arr_str})[{nums[3]}]^({arr_str})[{nums[4]}]',
            'p': f'({nums[1]}).[]^({arr_str})[[]]',
            'q': f'({nums[0]}).[]^({arr_str})[[]]',
            # 'r': f'({arr_str})[[[]]]',
            's': f'({nums[2]}).[]^({arr_str})[[]]',
            't': f'({nums[5]}).[]^({arr_str})[[]]',
            'u': f'({nums[4]}).[]^({arr_str})[[]]',
            'v': f'({nums[0]}).[]^({nums[4]}).[]^({arr_str})[[[]]]',
            'w': f'({nums[6]}).[]^({arr_str})[[]]',
            'x': f'({nums[0]}).[]^({nums[1]}).[]^({arr_str})[{nums[4]}]',
            # 'y': f"(({nums[0]}).{arr_str})[({nums[1]}).({nums[0]})]",
            'z': f'({nums[1]}).[]^({nums[2]}).[]^({arr_str})[{nums[4]}]',
            '{': f'({nums[0]}).[]^({nums[2]}).[]^({arr_str})[{nums[4]}]',
            '|': f'({nums[1]}).[]^({nums[4]}).[]^({arr_str})[{nums[4]}]',
            '}': f'({nums[0]}).[]^({nums[4]}).[]^({arr_str})[{nums[4]}]',
            '~': f'({nums[4]}).[]^({arr_str})[[]]^({arr_str})[[[]]]^({arr_str})[{nums[4]}]'})

    def encode(self, code, eval_mode=None):
        def clean_code(code):
            return code.replace('\n', '').replace(' ', '')

        def basic_encode(code):
            return '.'.join(
                [f"({self.char_mapping[c] if c in self.char_mapping else fix_missing_char(c)})" for c in code])

        def encode_number(num):
            return f"{self.nums[0]}+({'.'.join([self.nums[int(n)] for n in str(num)])})"

        def fix_missing_char(char, compatiable=True):
            # to compatiable with PHP < 7.2.0: `mb_chr` only support PHP >= 7.2.0
            if compatiable:
                str_getcsv = basic_encode("str_getcsv")
                mb_chr = basic_encode('IntlChar,chr')
                char_code = encode_number(ord(char))
                return f"({str_getcsv})({mb_chr})({char_code})"
            else:
                return f"({basic_encode('mb_chr')})({basic_encode(str(ord(char)))})"

        if eval_mode == 'create_function':
            code = code.replace('"', '""')

        code = basic_encode(code)

        if not eval_mode:
            return code

        elif eval_mode == 'create_function':
            create_function = basic_encode("create_function")
            str_getcsv = basic_encode("str_getcsv")
            comma = basic_encode(",")
            quote = basic_encode('"')

            """
            1. create_function(...str_getcsv(',"YOUR_CODE"') )
            2. create_function(...['', 'YOURCODE'])
            3. create_function('', 'YOURCODE')
            """

            eval_code = f"""({create_function})(
                ...({str_getcsv})({comma}.{quote}.{code}.{quote})
            )()
            """

        elif eval_mode == 'assert':  # only support PHP < 7.1
            assert_func = basic_encode('assert')
            prefix = basic_encode('(function(){')
            postfix = basic_encode(';return 1;})()')
            eval_code = f"""
            ({assert_func})(
                ({prefix}).({code}).({postfix})
            )
            """

        return clean_code(eval_code)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("code", help="any string to encode.")
    parser.add_argument("-O", "--output-file", dest="file",
                        help="write encoded string into some file.")
    parser.add_argument("-P", "--plain-string", dest="plain", action='store_true',
                        help="encode as plain string (without eval it).")
    parser.add_argument("-E", "--eval", dest="eval",
                        choices=['assert', 'create_function'], default='create_function',
                        help="choose eval mode. (`assert` mode only support PHP < 7.1)")
    args = parser.parse_args()

    code = args.code

    phpfun = PHPFun()

    if args.plain:
        encoded = phpfun.encode(code)
        assert (set(encoded) <= set('([.^])'))
    else:
        encoded = phpfun.encode(code, args.eval)
        assert (set(encoded[:-1]) <= set('([.^])'))
        encoded = "<?php " + encoded + " ?>\n"

    if args.file:
        with open(args.file, 'w') as f:
            f.write(encoded)
    else:
        print(encoded)

    if args.plain:
        print(f"Output as plain string, without eval it.")
    else:
        print(f"Using `{args.eval}` mode to eval.")

    print(len(encoded), "chars.")
