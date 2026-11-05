package org.umbral.core.net.pkt

/** Simple growable big-endian byte builder shared by packet and DNS codecs. */
class BytePacketWriter(capacity: Int = 512) {
    private var buf = ByteArray(capacity)
    private var len = 0

    fun u8(v: Int) { ensure(1); buf[len++] = v.toByte() }
    fun u16(v: Int) { u8(v shr 8); u8(v) }
    fun u32(v: Long) { u16((v shr 16).toInt()); u16(v.toInt()) }
    fun bytes(b: ByteArray) { ensure(b.size); b.copyInto(buf, len); len += b.size }

    private fun ensure(n: Int) {
        if (len + n > buf.size) {
            buf = buf.copyOf(maxOf(buf.size * 2, len + n))
        }
    }

    fun toByteArray() = buf.copyOf(len)
}
