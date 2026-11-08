from bisect import bisect_right
from itertools import pairwise


class MissingNumbers:
    def __init__(self, ordered):
        self.ranges = [(a + 1, b) for a, b in pairwise(ordered) if b - a > 1]
        self.count = sum(stop - start for start, stop in self.ranges)

    def __len__(self):
        return self.count

    def __iter__(self):
        return self.sample()

    def __contains__(self, number):
        if type(number) is not int:
            return False
        index = bisect_right(self.ranges, number, key=lambda bounds: bounds[0]) - 1
        return index >= 0 and number < self.ranges[index][1]

    def sample(self, step=1):
        offset = 0
        for start, stop in self.ranges:
            yield from range(start + (-offset % step), stop, step)
            offset += stop - start
