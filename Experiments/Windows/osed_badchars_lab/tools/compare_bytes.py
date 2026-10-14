from collections import namedtuple
ComparisonReport=namedtuple("ComparisonReport","matches mismatches missing_ranges truncation_at alignment_ambiguous")
def compare_bytes(expected,observed):
    mismatches=[(i,expected[i],observed[i]) for i in range(min(len(expected),len(observed))) if expected[i]!=observed[i]]
    return ComparisonReport(len(expected)-len(mismatches),mismatches,[(len(observed),len(expected))] if len(observed)<len(expected) else [],len(observed) if len(observed)<len(expected) else None,len(set(expected))<len(expected))
