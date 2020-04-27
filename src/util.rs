pub fn combine_u8_into_u16(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8) + (buf[1] as u16)
}

pub fn split_u16_into_u8(num: u16) -> [u8; 2] {
    [(num >> 8) as u8, (num & ((1 << 8) - 1)) as u8]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_combine_u8_into_u16() {
        assert_eq!(0x1234, combine_u8_into_u16(&[0x12, 0x34]));
        assert_eq!(0x4321, combine_u8_into_u16(&[0x43, 0x21]));
        assert_eq!(0x00FF, combine_u8_into_u16(&[0x00, 0xFF]));
        assert_eq!(0xFF00, combine_u8_into_u16(&[0xFF, 0x00]));
        assert_eq!(0xF00F, combine_u8_into_u16(&[0xF0, 0x0F]));
        assert_eq!(0x0FF0, combine_u8_into_u16(&[0x0F, 0xF0]));
    }

    #[test]
    fn test_split_u16_into_u8() {
        assert_eq!(&split_u16_into_u8(0x1234), &[0x12, 0x34]);
        assert_eq!(&split_u16_into_u8(0x4321), &[0x43, 0x21]);
        assert_eq!(&split_u16_into_u8(0x00FF), &[0x00, 0xFF]);
        assert_eq!(&split_u16_into_u8(0xFF00), &[0xFF, 0x00]);
        assert_eq!(&split_u16_into_u8(0xF00F), &[0xF0, 0x0F]);
        assert_eq!(&split_u16_into_u8(0x0FF0), &[0x0F, 0xF0]);
    }
}
