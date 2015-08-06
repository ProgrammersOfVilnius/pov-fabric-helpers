test:
	nosetests

coverage:
	coverage run -m nose

release:
	# pip install zest.releaser
	fullrelease
