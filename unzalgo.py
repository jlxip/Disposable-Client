'''
Original idea from: https://stackoverflow.com/questions/22277052/how-can-zalgo-text-be-prevented
'''

#!/usr/bin/env python
from __future__ import division
import unicodedata
import codecs
import numpy

ZALGO_CHAR_CATEGORIES = ['Mn', 'Me']
THRESHOLD = 0.5

def isWordZalgo(word):
	if len(word) == 0:
		return False
	cats = [unicodedata.category(c) for c in word]
	score = sum([cats.count(banned) for banned in ZALGO_CHAR_CATEGORIES]) / len(word)
	return score > THRESHOLD

def isZalgo(s):
    if len(s) == 0:
        return False
    word_scores = []
    for word in s.split():
        cats = [unicodedata.category(c) for c in word]
        score = sum([cats.count(banned) for banned in ZALGO_CHAR_CATEGORIES]) / len(word)
        word_scores.append(score)
    total_score = numpy.percentile(word_scores, 75)
    return total_score > THRESHOLD

def fixWordZalgo(word):
	if not isWordZalgo(word):
		return word
	return ''.join([c for c in unicodedata.normalize('NFD', word) if unicodedata.category(c) not in ZALGO_CHAR_CATEGORIES])

def fixZalgo(s):
	if not isZalgo(s):
		return s
	return ' '.join([fixWordZalgo(word) for word in s.split()])
