test:
	py.test tests.py

coverage:
	coverage run -m py.test tests.py

release:
	# pip install zest.releaser
	fullrelease
