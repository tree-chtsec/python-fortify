# object representing a Fortify issue
class Issue:
	def __init__(self, id, severity):
		self.id=id
		self.severity=severity
		self.analysis=''

	def isNaI(self):
		return self.analysis == 'Not an Issue'

	def severityText(self):
		# TODO:  1.0 is a valid value - is that also mapped to Low?
		textMap = {"2.0" : "Low",
			   "3.0" : "Medium",
			   "4.0" : "High",
			   "5.0" : "Critical",
		}
		return textMap[self.severity]
