#!/usr/bin/env python3

# playground for testing labelConverter logic in Python first

all_valid = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,"
    b"-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95"
    b"\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba"
    b"\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
all_bytes = bytes(range(256))
brief = b"-0123456789_abcdefghijklmnopqrstuvwxyz"
testing = b"123"

# limited to 3 byte labels for testing
LABEL_LIMIT = 3
ALPHABET = testing


class LabelConverter:
    def __init__(self, alphabet: bytes, label_limit: int) -> None:
        self.alphabet = alphabet
        self.alphabet_len = len(self.alphabet)
        self.label_limit = label_limit

        self._set_mults()
        self.max_label = self.alphabet[-1:] * self.label_limit

    def _set_mults(self) -> None:
        mult = 0
        mults = []
        for i in range(self.label_limit):
            mult *= self.alphabet_len
            mult += 1
            mults.append(mult)

        self.mults = mults
        self.max_label_num = mult * self.alphabet_len - 1

    def _label_is_valid(self, label: bytes) -> bool:
        return len(label) <= self.label_limit and all(v in self.alphabet for v in label)

    def _num_is_valid(self, num: int) -> bool:
        return 0 <= num <= self.max_label_num

    def label_to_num(self, label: bytes) -> int:
        if not self._label_is_valid(label):
            raise ValueError("invalid label")

        mult_i = self.label_limit - 1

        ret = len(label) - 1
        for v in label:
            ret += self.alphabet.index(v) * self.mults[mult_i]
            mult_i -= 1

        return ret

    def num_to_label(self, num: int) -> bytes:
        if not self._num_is_valid(num):
            raise ValueError("invalid nums")

        mult_i = self.label_limit - 1

        ret = bytearray()
        while num >= 0:
            chunk, num = divmod(num, self.mults[mult_i])
            ret.append(self.alphabet[chunk])
            num -= 1
            mult_i -= 1
        return ret

    def increment_label(self, label: bytearray) -> bytearray:
        if not self._label_is_valid(label):
            raise ValueError("invalid label")
        if label == self.max_label:
            raise ValueError("incrementing max label")

        if len(label) < self.label_limit:
            return label + self.alphabet[:1]

        if label == self.max_label:
            raise ValueError("max label incremented")

        while label:
            if label[-1] != self.alphabet[-1]:
                label[-1] = self.alphabet[self.alphabet.index(label[-1]) + 1]
                return label
            label = label[:-1]

        raise Exception("idk")

    def next_with_len(
        self, num: int, length: int, repeat_ok: bool = True
    ) -> int | None:
        if not (self._num_is_valid(num) and length < self.label_limit):
            return None

        if not repeat_ok:
            num += 1

        while True:
            if num > self.max_label_num:
                return None

            label = self.num_to_label(num)
            if len(label) == length:
                return num
            if len(label) < length:
                num += length - len(label)
                continue

            # too long; seek to end of this branch
            v = len(self.alphabet) - self.alphabet.index(label[-1])
            v *= self.mults[len(self.mults) - len(label)]
            num += v

    def _next_with_len_lazy(
        self, num: int, length: int, repeat_ok: bool = True
    ) -> int | None:
        if not (self._num_is_valid(num) and length < self.label_limit):
            return None

        if not repeat_ok:
            num += 1

        while True:
            if num > self.max_label_num:
                return None
            label = self.num_to_label(num)
            if len(label) == length:
                return num
            num += 1

    def prev_with_len(
        self, num: int, length: int, repeat_ok: bool = True
    ) -> int | None:
        if not (self._num_is_valid(num) and length < self.label_limit):
            return None

        if not repeat_ok:
            num -= 1

        while True:
            if num < 0:
                return None

            label = self.num_to_label(num)
            if len(label) == length:
                return num
            if len(label) < length:
                num -= max(len(label) - 1, 1)
                continue
            v = self.alphabet.index(label[-1])
            v *= self.mults[len(self.mults) - len(label)]
            v += 1
            num -= v

    def _prev_with_len_lazy(
        self, num: int, length: int, repeat_ok: bool = True
    ) -> int | None:
        if not (self._num_is_valid(num) and length < self.label_limit):
            return None

        if not repeat_ok:
            num -= 1

        while True:
            if num < 0:
                return None

            label = self.num_to_label(num)
            if len(label) == length:
                return num
            num -= 1

    def _exhaust(self) -> None:
        label = bytearray(b"")

        i = -1
        while label != self.max_label:
            label = self.increment_label(label)
            i += 1
            if i != self.label_to_num(label):
                raise Exception(
                    f"label_to_num, function {self.label_to_num(label)}, real {i} for {label=}"
                )
            if self.num_to_label(i) != label:
                raise Exception(
                    f"num_to_label, function {self.num_to_label(i)!r}, real {label} for {i=}"
                )

            for length in range(1, 4):
                if self._next_with_len_lazy(i, length) != self.next_with_len(i, length):
                    raise Exception(
                        f"next_with_len {length=}, lazy {self._next_with_len_lazy(i, length)}, fast {self.next_with_len(i, length)} for {i=} {self.mults}"
                    )

                if self._prev_with_len_lazy(i, length) != self.prev_with_len(i, length):
                    raise Exception(
                        f"prev_with_len {length=}, lazy {self._prev_with_len_lazy(i, length)}, fast {self.prev_with_len(i, length)} for {i=} {self.mults}"
                    )

            # if len(label) == 1:
            if True:
                print(i, bytes(label))


def main() -> None:
    # go_max = 1880885545219653107853456787374009556234828844768999971927206913249812513217768324470216076325311940
    # print(f"{go_max}\n{MAX_LABEL_NUM}")
    # print(num_to_label(go_max))

    # 1485428123653067760150123324866389102938026711798343748918466215158701438364297665313296513516574457
    # 1 length 17 iter 2283566
    #    num = 1485428123653067760150123324866389102938026711798343748918466215158701438364297665313296513516574457
    #    print(bytes(num_to_label(num)))
    #
    #    nlen = next_with_len(num, 17)
    #    print(bytes(num_to_label(nlen)))
    #
    #    return
    # lc = LabelConverter(ALPHABET, LABEL_LIMIT)
    lc = LabelConverter(all_valid, 63)
    print(lc.max_label_num)
    print(lc.mults)
    print(lc.num_to_label(lc.max_label_num))
    # lc._exhaust()


if __name__ == "__main__":
    main()
