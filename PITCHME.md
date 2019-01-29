# Let's Get Started

---

## Add Some Slide Candy

![](assets/img/presentation.png)

---
@title[Customize Slide Layout]

@snap[west span-50]
## Customize Slide Content Layout
@snapend

@snap[east span-50]
![](assets/img/presentation.png)
@snapend

---?color=#E58537
@title[Add A Little Imagination]

@snap[north-west]
#### Add a splash of @color[cyan](**color**) and you are ready to start presenting...
@snapend

@snap[west span-55]
@ul[spaced text-white]
- You will be amazed
- What you can achieve
- *With a little imagination...*
- And **GitPitch Markdown**
@ulend
@snapend

@snap[east span-45]
@img[shadow](assets/img/conference.png)
@snapend

---?image=assets/img/presenter.jpg

@snap[north span-100 headline]
## Now It's Your Turn
@snapend

@snap[south span-100 text-06]
[Click here to jump straight into the interactive feature guides in the GitPitch Docs @fa[external-link]](https://gitpitch.com/docs/getting-started/tutorial/)
@snapend

---

## What is CORS?

@snap[south span-100]
@ul[spaced text-white]
- [Cross-origin resource sharing @fa[external-link]](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) is a mechanism that allows restricted resources on a web page to be requested from another domain outside the domain from which the first resource was served
@ulend
@snapend

---

## What is [Same Origin Policy @fa[external-link]](http://en.wikipedia.org/wiki/Same-origin_policy)?

@ul[spaced text-white]
- Cross-domain AJAX requests were not allowed due to their ability to perform requests with malicious data, tailored headers, and non-idempotent request sequences to read and manipulate data
@ulend

---

## What's an origin?
@ul[spaced text-white]
- @quote[...user-agents group URIs together into protection domains called “origins”. Roughly speaking, two URIs are part of the same origin (i.e., represent the same principal) if they have the same scheme, host, and port...]
- [The Web Origin Concept](https://www.ietf.org/rfc/rfc6454.txt)
@ulend

---

## What is CORS?

@ul[spaced text-white]
- The conventional browser security model prevents HTTP requests from one origin to another
- CORS extends the traditional security model present in web browsers
- By defining a communication protocol that allows involved parties to gather information about each other
@ulend

---

## What is CORS?
@ul[spaced text-white]
- In CORS, this model is extended by allowing the server-application to verify requests’ origins, by adding specific headers to allow the user-agent to verify the policies enforced by the server and including mechanisms to make queries before sending “complex requests”. CORS adds the Origin header in all CORS requests in order to inform the server-side application with data about where the requests are coming from.
@ulend

---

## Why CORS?

@ul[spaced text-white]
- Web developers were coming up with creative ways to request and integrate data from domains outside their control. The W3C decided to step in and attempt to standardize sharing resources.
- While this capability was in fact around for many years, for simple elements, such as images, ECMAScript (JavaScript) code was not allowed to make such requests, mainly due to the same-origin security policy, implemented by all major browsers.
@ulend

---

## Without the same-origin policy a bad actor could take advantage:
- A user visits malicious.com
- The browser allows client-side javascript to make an AJAX request to another domain
- The requested domain happens to be the user's banking provider

---

## What is CORS (frontend)?

@ul[spaced text-white]
- @quote[CORS is a mechanism to enable client-side cross-origin requests. In summary, it allows requests to be identified by their origin, while the server-side application is able to verify security restrictions, informing the browser if a request is permitted.]
@ulend

---

## What is CORS (backend)?

@ul[spaced text-white]
- CORS is a mechanism to allow server-side web applications to expose resources to all or a restricted set of domains.
- The primary mechanism is HTTP request headers.
- A web client tells a web server its source domain using the HTTP request header "Origin".
@ulend

---

## Here's an example of a client HTTP request with origin...

---

## Why should we understand CORS?

---

## What is [XHR @fa[external-link]](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest)?

---

## What is XSS?

---

## What are the best practices?

---

## What should developers be doing?

---

## How does this affect frontend development?

---

## How does this affect backend development?

---

## How does this affect the QA process?

---

## What is the modern browser security model?

---

@quote[Due to those facts, we want to highlight the importance of recognizing that a system will have its security level lowered to the lowest level of all applications that include their contents into an aggregated document when facing the assessed vulnerabilities; thus, allowing other domains to use an application as a part of a bigger project is effectively a responsibility transfer.]

---

@quote[Our findings indicate that vulnerabilities exploitable by targeting client side technologies in an application issuing CORS requests will lead to vulnerabilities in the original system, even if it has been hardened by conventional techniques to resist against such types of attack.]

---

## What are some of the common vulnerabilities?
- XSS
- CSRF
- SQL-injection
- Misconfiguration

---

## What is Cross-site scripting (XSS)?

- An XSS vulnerability is present when a client-side application unwittingly executes malicious script
- Malicious code is injected into a web application from improperly neutralized input
- Most commonly, this is data injected into a backend database and used to dynamically generate a web page or data requested by a client-side application
- The malicious script executes under the same domain as the web server
- The server will see any request by the client as legit and sharing the same session as a trusted user

---

## What are the XSS types?

---

## Example XSS diagram

---

## Example XSS code

---

## Example XSS input form

---

## What can we do to prevent XSS vulnerabilities (frontend)?

---

## What can we do to prevent XSS vulnerabilities (backend)?

---

## What is OWASP?

@ul[spaced text-white]
- [The Open Web Application Security Project (OWASP), an online community, produces freely-available articles, methodologies, documentation, tools, and technologies in the field of web application security](https://en.wikipedia.org/wiki/OWASP)
@ulend

---

## Recommended Security Practice - Backend
For these reasons, the server-side application is ultimately responsible for enforcing its security policies for every resource. Additionally, in no circumstance the origin should be used in security controls as the only authentication/security mechanism, if they are judged to be necessary.

---

### References
- [CORS and well-known vulnerabilities](https://www.e-systems.tech/est-framework/-/knowledge_base/cors/cors)
- [OWASP CORS Header Scrutiny](https://www.owasp.org/index.php/CORS_OriginHeaderScrutiny)
- [OWASP ASVS](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
- [OWASP Cheatsheet](https://www.owasp.org/index.php/OWASP_Cheat_Sheet_Series)
- [OWASP Proactive Controls for Developers](https://www.owasp.org/index.php/OWASP_Proactive_Controls)
- [OWASP HTML5 Cheatsheet on CORS](https://www.owasp.org/index.php/HTML5_Security_Cheat_Sheet#Cross_Origin_Resource_Sharing)
- Cross-site Scripting - Improper Neutralization of Input(https://cwe.mitre.org/data/definitions/79.html)