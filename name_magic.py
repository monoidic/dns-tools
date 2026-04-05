#!/usr/bin/env python3

from label_magic import LabelConverter

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

LABEL_LIMIT = 3
ALPHABET = testing
MAX_NAME_LEN = 11

BA_DOT = bytearray(b".")

DO_LOG = False


if DO_LOG:
    log = print
else:
    log = lambda *x: None


class NameConverter:
    def __init__(self, alphabet: bytes, label_limit: int, max_name_len: int) -> None:
        self.les = [LabelConverter(alphabet, lim) for lim in range(label_limit + 1)]
        self.alphabet = alphabet
        self.label_limit = label_limit
        self.max_name_len = max_name_len

        self.max_name = self._get_max_name()
        self.step_diffs = self._mk_step_diffs()
        self.expand_diffs = self.mk_expand_diffs()
        self.max_name_num = self.step_diffs[-1][0] * len(alphabet)

    def _get_max_name(self) -> bytes:
        max_label = self.alphabet[-1:] * self.label_limit
        max_label_pref = bytes([len(max_label)]) + max_label

        # account for null term at end + size before each label
        max_label_l_count = (self.max_name_len - 1) // (self.label_limit + 1)
        max_name = max_label_pref * max_label_l_count + b"\x00"
        if len(max_name) + 2 <= self.max_name_len:
            pref = self.alphabet[-1:] * (self.max_name_len - len(max_name) - 1)
            pref = bytes([len(pref)]) + pref
            max_name = pref + max_name

        return max_name

    def _get_max_name_dot(self) -> bytes:
        # dot version
        max_label = self.alphabet[-1:] * self.label_limit
        max_label_pref = b"." + max_label

        # account for null term at end + size before each label
        max_label_l_count = (self.max_name_len - 1) // (self.label_limit + 1)
        max_name = max_label_pref * max_label_l_count + b"."
        if len(max_name) + 2 <= self.max_name_len:
            pref = self.alphabet[-1:] * (self.max_name_len - len(max_name) - 1)
            pref = b"." + pref
            max_name = pref + max_name

        return max_name

    def increment_name(self, name: bytearray) -> bytearray | None:
        if name == self.max_name:
            return None

        labels = self._name_to_labels(name)

        can_insert_new_label = len(name) + 2 <= MAX_NAME_LEN
        if can_insert_new_label:
            labels.insert(0, bytearray(self.alphabet[:1]))
            log("inserted new label")
            return self._name_from_labels(labels)

        can_extend_first_label = (
            len(name) + 1 <= MAX_NAME_LEN and len(labels[0]) < self.label_limit
        )
        if can_extend_first_label:
            labels[0] += self.alphabet[:1]
            log("extended label")
            return self._name_from_labels(labels)

        first_label = labels[0]
        le = self.les[len(first_label)]
        if first_label != le.max_label:
            pre_update = bytes(first_label)
            post_update = le.increment_label(first_label)
            labels[0] = post_update
            log(f"incremented label from {pre_update} to {bytes(post_update)}")
            return self._name_from_labels(labels)

        # first was max
        # this removes at least 2 bytes; no size checks needed in below loop
        labels = labels[1:]

        # increment upwards, to a max of self.label_limit
        while labels:
            first_label = labels[0]
            if len(first_label) < self.label_limit:
                labels[0] = first_label + self.alphabet[:1]
                log("upwards, extended label")
                return self._name_from_labels(labels)
            # is at label limit
            le = self.les[len(first_label)]
            if first_label != le.max_label:
                labels[0] = le.increment_label(first_label)
                log("upwards, incremented label")
                return self._name_from_labels(labels)
            # is also max label; increment next label
            labels = labels[1:]

        raise Exception("wtf")

    def _name_to_labels(self, name: bytearray) -> list[bytearray]:
        if not (1 <= len(name) <= self.max_name_len and name[-1] == 0):
            raise ValueError(f"invalid name {len(name)} {self.max_name_len}")

        ret: list[bytearray] = []
        while name != b"\x00":
            label_len = name[0]
            label = name[1 : label_len + 1]
            if len(label) != label_len or label_len > self.label_limit:
                raise ValueError("invalid name")
            name = name[label_len + 1 :]
            ret.append(label)
        return ret

    def _name_from_labels(self, labels: list[bytearray]) -> bytearray:
        ret = bytearray()
        for label in labels:
            # *should* be fine without a check, but better safe than sorry
            if len(label) > self.label_limit:
                raise ValueError("invalid labels")
            ret.append(len(label))
            ret.extend(label)

        ret.append(0)
        return ret

    def _name_to_labels_dot(self, name: bytearray) -> list[bytearray]:
        # dot, for testing only, replacement needed for alphabets with dot
        if not (1 <= len(name) <= self.max_name_len and name[-1:] == BA_DOT):
            raise ValueError(f"invalid name {len(name)} {self.max_name_len}")

        # discard prefix dot
        name = name[1:]

        if not name:
            return []
        return name.split(BA_DOT)[:-1]

    def _name_from_labels_dot(self, labels: list[bytearray]) -> bytearray:
        # dot, for testing only, replacement needed for alphabets with dot
        if not labels:
            return BA_DOT
        return BA_DOT + BA_DOT.join(labels) + BA_DOT

    def _exhaust(self) -> None:
        name = self._name_from_labels([])
        i = 0

        print(i, bytes(name), len(name))

        if self.num_to_name(i) != name:
            raise Exception("aww ptooey")
        if self.name_to_num(name) != i:
            raise Exception("aww ptooey")

        # while i < self.max_name_num:
        while name != self.max_name:
            name = self.increment_name(name)
            assert name
            i += 1
            if True:
                print(i, bytes(name), len(name))
                pass

            if self.num_to_name(i) != name:
                raise Exception("aww ptoeey")
            if self.name_to_num(name) != i:
                raise Exception("aww ptooey")

    def next_with_len(
        self, name: bytearray, length: int, repeat_ok: bool = True
    ) -> bytearray | None:
        # length is number of labels here cuz why not lol
        # TODO
        raise Exception("unimplemented")
        if not repeat_ok:
            incremented = self.increment_name(name)
            if not incremented:
                return None
            name = incremented

        pass
        return None

    def prev_with_len(
        self, name: bytearray, length: int, repeat_ok: bool = True
    ) -> bytearray | None:
        # TODO
        raise Exception("unimplemented")

    def _mk_step_diffs(self) -> list[list[int]]:
        diffs = [[0] * self.label_limit for i in range(self.max_name_len - 2)]
        self._step_diffs_recursive(diffs, self.max_name_len - 3, 0)
        return diffs

    def _step_diffs_recursive(
        self,
        diffs: list[list[int]],
        spaces_to_left: int,
        leftmost_label_len: int,
    ) -> int:
        num = diffs[spaces_to_left][leftmost_label_len]
        if num != 0:
            return num

        room_for_new_label = spaces_to_left >= 2
        room_for_label_expansion = (
            spaces_to_left >= 1 and (leftmost_label_len + 1) < self.label_limit
        )

        if room_for_new_label:
            num += self._step_diffs_recursive(diffs, spaces_to_left - 2, 0)
        if room_for_label_expansion:
            num += self._step_diffs_recursive(
                diffs,
                spaces_to_left - 1,
                leftmost_label_len + 1,
            )

        num *= len(self.alphabet)
        num += 1
        diffs[spaces_to_left][leftmost_label_len] = num
        return num

    def mk_expand_diffs(self) -> list[int]:
        ret = [0] * (self.max_name_len - 2)

        for spaces_to_left in range(1, self.max_name_len - 1):
            idx = self.max_name_len - 4 - spaces_to_left
            # assert idx >= 0
            if idx < 0:
                ret[spaces_to_left - 1] = 1
            else:
                ret[spaces_to_left - 1] = (
                    self.step_diffs[idx][0] * len(self.alphabet) + 1
                )

        return ret

    def _valid_num(self, num: int) -> bool:
        return 0 <= num <= self.max_name_num

    def num_to_name(self, num: int) -> bytearray | None:
        if not self._valid_num(num):
            return None

        if not num:
            return self._name_from_labels([])

        num -= 1
        labels = [bytearray(self.alphabet[:1])]

        while num > 0:
            if any(
                (len(label) > self.label_limit or len(label) == 0) for label in labels
            ):
                raise Exception("aww")

            # try step; go back to start if successful
            # try expand; go back to start if successful
            # add new label, decrement 1

            # step
            current_name_len = sum(len(label) for label in labels) + len(labels) + 1
            spaces_to_left = self.max_name_len - current_name_len
            leftmost_label_len = len(labels[0])
            step = self.step_diffs[spaces_to_left][leftmost_label_len - 1]
            steps, num = divmod(num, step)
            if steps:
                old_v_idx = self.alphabet.index(labels[0][-1:])
                new_v_idx = old_v_idx + steps
                new_v = self.alphabet[new_v_idx : new_v_idx + 1]
                labels[0][-1:] = new_v
                log(f"stepping {step=}")
                continue

            # expand
            idx = self.max_name_len - spaces_to_left - 3
            if leftmost_label_len < self.label_limit and idx >= 0:
                expand = self.expand_diffs[idx]
                if expand <= num:
                    num -= expand
                    labels[0].extend(self.alphabet[:1])
                    log(f"expanding {expand=}")
                    continue

            # add new label
            num -= 1
            labels.insert(0, bytearray(self.alphabet[:1]))

        return self._name_from_labels(labels)

    def name_to_num(self, name: bytearray) -> int | None:
        # TODO validate here?
        labels = self._name_to_labels(name)
        log(f"start {labels=}")

        num = 0

        while labels:
            pass
            # opposite of num_to_name
            # return if no more labels
            # if label is just self.alphabet[:1], then remove it and add 1
            # if last label can contract since label[-1:] == self.alphabet[:1], then contract and add expand value
            # last label has to be steppable

            first_label = labels[0]

            # stray end label
            if first_label == self.alphabet[:1]:
                num += 1
                labels.pop(0)
                log(f"stray end label {labels=} {num=}")
                continue

            current_name_len = sum(len(label) for label in labels) + len(labels) + 1
            spaces_to_left = self.max_name_len - current_name_len

            # negate expansion
            if first_label[-1:] == self.alphabet[:1]:
                idx = self.max_name_len - spaces_to_left - 3 - 1
                expand = self.expand_diffs[idx]

                num += expand
                labels[0] = first_label[:-1]
                log(f"negate expansion {labels=} {num=}")
                continue

            # step
            leftmost_label_len = len(first_label)
            step = self.step_diffs[spaces_to_left][leftmost_label_len - 1]
            mult = self.alphabet.index(first_label[-1:])
            step *= mult

            num += step
            labels[0][-1:] = self.alphabet[:1]
            log(f"step {labels=} {num=}")

        return num


def main() -> None:
    # nc = NameConverter(ALPHABET, LABEL_LIMIT, MAX_NAME_LEN)
    # nc._exhaust()
    nc = NameConverter(all_valid, 63, 255)

    print(nc.step_diffs)
    print(nc.expand_diffs)

    print(nc.max_name)
    print(nc.max_name_num)


if __name__ == "__main__":
    main()
