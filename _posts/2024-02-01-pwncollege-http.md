---
layout: post
title:  "Pwn College - HTTP"
date:   2024-02-01 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module delves deep into manipulating HTTP requests and responses. It focuses on headers, paths, arguments, form data, JSON, cookies and redirects. 

## Setup

All challenges are running a flask server within `/challenge/run`, listening on `localhost:80`. 

## Intro

Example of static HTTP request: `GET /cat.gif HTTP/1.0`. The remote server communicates with the client (browser) on a standardized protocol, `HTTP-1.0`, and fetches from the requested path a file. \
Example of static HTTP response: `HTTP/1.0 200 OK`, denoting success (along with the requested resource too). \
Example of dynamic HTTP request: `GET /tmp?tz=UTC HTTP/1.0` \
Example of dynamic HTTP response: `HTTP/1.0 200 OK\nContent-Type: text/plain\nContent-Length: 19\r\n\<dynamic_data>`.

HTTP runs over TCP.

## RFC-1945


