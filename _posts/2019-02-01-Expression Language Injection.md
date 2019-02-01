---
title: Remote Code execution with EL Injection Vulnerabilities
---

## Introduction

An expression language makes it possible to easily access application data. For example, the JSP expression language allows a page author to access a bean using simple syntax such as ${name} for a simple variable [1].

EL Injection occurs when user input is embedded in an unsafe manner. EL Injection are very serious and lead to complete compromise of the application&#39;s data and functionality and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point. Also EL Injection can be used to bypass input filters and any HttpOnly protection for application pages vulnerable to cross-site scripting (XSS) [2].

This paper I wrote defines a methodology for detecting and exploiting EL injection.
[ExpressionLanguageInjection.pdf](https://github.com/zerosecuritylab/Whitepaper/blob/master/Remote%20Code%20execution%20with%20EL%20Injection%20Vulnerabilities.pdf)
