# base64 url decoding

Per the spec
[https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/]:
"*Base64url* denotes the URL-safe base64 encoding without padding defined in
Section 2 of [RFC7515]."

Thus, we consider the '=' character as illegal.

## Output of espresso minimization

```
$ ./espresso  -Dverify  -Dexact -oeqntott base64.espresso
...
o6 = (!v4&!v3&!v2&!v1&!v0) | (v4&v3&!v2&v1&v0) | (v5&v4&v3&v1&v0) | (!v6
    &v3&v2&!v0) | (v4&v3&v2&!v1) | (v4&v3&v2&!v0) | (!v6&!v4&!v3) | (!v6
    &!v4&!v2) | (!v6&v3&v1) | (!v6&!v5) | (v7);

o5 = (v6&v5&v4&!v3&!v2) | (v6&v5&v4&!v3&!v0) | (v6&v5&v4&v2&!v1) | (v5&v2
    &v1&v0) | (v4&v3&v1&v0) | (v5&v3) | (!v6&!v2) | (!v6&v2);

o4 = (v5&!v4&!v3&!v1) | (v5&!v4&!v3&!v2) | (!v5&v4&v1) | (v5&!v4&!v3&!v0) | (
    v4&v2&v1&v0) | (!v5&v4&v0) | (!v5&v4&v2) | (v4&v3) | (!v6&!v2) | (!v6
    &v2);

o3 = (v6&!v3&!v2&!v1&!v0) | (v6&v5&v4&!v3&!v2) | (v6&v5&v4&!v3&!v0) | (
    v6&v5&v4&v2&!v1) | (v5&!v4&!v3&!v1) | (v5&!v4&!v3&!v2) | (v5&!v4&!v3
    &!v0) | (!v5&v3&v1) | (v3&v2&v1&v0) | (!v5&v3&v0) | (!v5&v3&v2) | (
    !v6&v3) | (!v6&v2);

o2 = (v5&!v4&v2&!v1&v0) | (v6&v5&v4&v2&!v1) | (!v5&!v2&!v1&!v0) | (v6&v5
    &v2&!v0) | (v5&!v2&v1&v0) | (!v5&v2&v0) | (!v5&v2&v1) | (!v6&!v2);

o1 = (v5&!v4&v2&!v1&v0) | (v6&v5&!v1&v0) | (!v5&!v1&!v0) | (!v5&v1&v0) | (
    v5&v1&!v0) | (!v6&v1);

o0 = (v4&v3&v1&v0) | (!v6&v4&v0) | (v6&!v0);
```
