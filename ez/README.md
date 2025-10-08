# Slightly easier (de)serialization

Arkworks' ark_serialize::{CanonicalDeserialize,CanonicalSerialize} are
idomatic and painless, assuming you like io::{Read,Write}, but their
non-compressed mess confuses some folks, so this hides non-compressed
serialization.

You might prefer ark-scale instaed for substrate of course.

