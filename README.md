# Damn Vulnerable Node Application - DEP
## How to harden a ‘Damn Vulnerable Node Application’ against common vulnerabilities 


---
# Project Info

- Name:  			DVNA-DEP Website Security Project
- Requirements: 		https://bit.ly/2SE4dib
- Project Partner: William Pfeil
- Course: CS467 Summer 2021Department: Oregon State University EECS 
- Team and Contact Information:
Patrick Byrne			byrnepat@oregonstate.edu
Seok Choi (aka Dan)		choiseok@oregonstate.edu
Elaine Laguerta		laguerte@oregonstea.edu

# Explanation of Our Project Name

The DVNA of the DVNA-DEP stands for Damn Vulnerable NodeJS Application, which is Appsecco’s NodeJS variation of the famous PHP web app Damn Vulnerable Web App (DVWA).  The DEP of the DVNA-DEP stands for “Dan”, “Elaine”, and “Patrick”, who are the three members of this project’s development group.  This project (DVNA-DEP) modifies code from Appsecco’s DVNA to expand and create our own version of a vulnerable NodeJS web app, which can act as a sandbox for cyber attacks.  Ultimately, a user will be presented with multiple versions/options of this web app, which vary in its vulnerability (from very vulnerable to heavily fortified against cyber attacks).

# Background of Our Project

The Internet developed organically, beginning with a small network between colleagues. Its functionality and design ethos depended on trusted users, a default attitude which arguably persists today, despite our best efforts. However, the Internet has grown past the initial set of trusted users, to encompass over half of the global population as of 2019 [1]. Naturally this population includes bad actors. These actors are incredibly diverse - of different demographics, means, and driven by various motivations - but all succeed in violating the mutual trust that supports the Internet by exploiting a common set of vulnerabilities.

This common set of vulnerabilities was codified by the OWASP foundation, first in 2013 and then revised in 2017, as a list of 10 vulnerabilities that  “represents a broad consensus about the most critical security risks to web applications” [2].  These vulnerabilities were found to occur across platforms and development stacks, in 114,000 applications from various organizations in 2017. The data call for 2021 has already received more than double the data points as compared to the 2017 call, suggesting that vulnerabilities continue to be exploitable. [3]

It is not possible to develop a new, more secure Internet to replace the current Internet. Even as web development stacks and tools evolve, and are even phased out and replaced by the “latest and greatest” libraries, every step forward must consider and reconsider the vulnerabilities posed by a default attitude of trust.

The purpose of this project is to explore the OWASP Top 10 vulnerabilities within the context of a node.js application. We will demonstrate how to harden the application against the vulnerabilities, with the hope that it can provide a model for hardening node.js and other applications. 

# Program Description

The user will be presented with a link to a private Github repository.  This repo will contain all necessary code and how-to documentation for a web application. The documentation will include both how to run the application and how to use it.

The user should be able to run repo’s code on a local machine, a server, a virtual machine, or docker. While the user has diverse options, documentation will point the user to run the code on docker.

When the code is run, the user will see a simple web app.  However, the purpose of this web app is as a sandbox for cyber attacks from another machine (e.g., kali linux running on a virtual machine).  The app will have user accounts and authentication. It will also have user input, a database, and whatever else is needed to offer a target for attacks.

The final demonstration of this project will have different versions of the web app that are vulnerable / not vulnerable to the various attacks and/or options to turn on or off vulnerabilities.  The user should be able to test attacks against our web app at varying difficulty levels. 

# References
1. Wikipedia contributors. List of countries by number of Internet users. Wikipedia, The Free Encyclopedia. June 30, 2021. Available at: https://en.wikipedia.org/w/index.php?title=List_of_countries_by_number_of_Internet_users&oldid=1031179313. Accessed June 30, 2021.

2. OWASP. OWASP Top Ten. 2017. Available at: https://owasp.org/www-project-top-ten/. Accessed June 30, 2021.

3. OWASP. The Data. 2021. Available at: https://www.owasptopten.org/thedata. Accessed June 30, 2021.

4. appsecco. Damn Vulnerable NodeJS Application, source code. Available at: https://github.com/appsecco/dvna. Accessed June 30, 2021. 

5. elaguerta. DVNA-DEP, source code. Available at: https://github.com/elaguerta/dvna-dep. 

6. appseco. Damn Vulnerable NodeJS Application, handbook. Available at:  https://appsecco.com/books/dvna-developers-security-guide. Accessed June 30, 2021.
