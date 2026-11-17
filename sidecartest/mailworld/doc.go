// §15's receive path on T2 in one process, MailWorld (world.go), for S7, the mail privacy rows, FS-13 and FS-121
// (MAIL-M7-27). It sits apart from sidecartest because it builds evs's engine, whose own tests import sidecartest. Only
// the sidecar_testhooks build has the world, since the TLS front's test listener it hands streams to is a testhooks
// type; on every other leg this package is empty.
package mailworld
