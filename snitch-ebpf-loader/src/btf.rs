//! Minimal BTF reader: just enough to find struct member offsets in
//! /sys/kernel/btf/vmlinux. This replaces CO-RE relocations, which Rust BPF
//! programs can't emit yet.
//!
//! Format: https://docs.kernel.org/bpf/btf.html
use eyre::{bail, ContextCompat, Result, WrapErr};
use std::path::Path;

const BTF_MAGIC: u16 = 0xeb9f;

const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

#[derive(Clone, Copy)]
struct Type {
    name_off: u32,
    kind: u32,
    vlen: u32,
    kind_flag: bool,
    /// `size` or `type`, depending on kind
    size_or_type: u32,
    /// byte offset of the kind-specific trailing data in `data`
    extra: usize,
}

pub struct Btf {
    data: Vec<u8>,
    str_start: usize,
    str_end: usize,
    /// indexed by type id; id 0 is void
    types: Vec<Type>,
}

/// A struct member's location.
#[derive(Clone, Copy, Debug)]
pub struct Member {
    pub offset: u32,
    pub size: u32,
}

impl Btf {
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() < 24 {
            bail!("BTF blob too short");
        }
        let magic = u16::from_ne_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            bail!("bad BTF magic {magic:#x} (wrong endianness?)");
        }
        let hdr_len = u32_at(&data, 4)? as usize;
        let type_off = u32_at(&data, 8)? as usize;
        let type_len = u32_at(&data, 12)? as usize;
        let str_off = u32_at(&data, 16)? as usize;
        let str_len = u32_at(&data, 20)? as usize;

        let types_start = hdr_len + type_off;
        let types_end = types_start + type_len;
        let str_start = hdr_len + str_off;
        let str_end = str_start + str_len;
        if types_end > data.len() || str_end > data.len() {
            bail!("BTF section bounds exceed blob size");
        }

        let mut types = vec![Type {
            name_off: 0,
            kind: 0,
            vlen: 0,
            kind_flag: false,
            size_or_type: 0,
            extra: 0,
        }];
        let mut pos = types_start;
        while pos < types_end {
            let name_off = u32_at(&data, pos)?;
            let info = u32_at(&data, pos + 4)?;
            let size_or_type = u32_at(&data, pos + 8)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = info & 0xffff;
            let extra = pos + 12;
            let trailing = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => 12 * vlen as usize,
                KIND_ENUM | KIND_FUNC_PROTO => 8 * vlen as usize,
                KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
                | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                other => bail!("unknown BTF kind {other} at offset {pos}"),
            };
            types.push(Type {
                name_off,
                kind,
                vlen,
                kind_flag: info >> 31 == 1,
                size_or_type,
                extra,
            });
            pos = extra + trailing;
        }

        Ok(Self {
            data,
            str_start,
            str_end,
            types,
        })
    }

    fn name(&self, off: u32) -> &str {
        let start = self.str_start + off as usize;
        if start >= self.str_end {
            return "";
        }
        let bytes = &self.data[start..self.str_end];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).unwrap_or("")
    }

    /// Skip typedefs and qualifiers.
    fn resolve(&self, mut id: u32) -> u32 {
        for _ in 0..32 {
            let t = &self.types[id as usize];
            match t.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                    id = t.size_or_type
                }
                _ => return id,
            }
        }
        id
    }

    fn size_of(&self, id: u32) -> Option<u32> {
        let t = &self.types[self.resolve(id) as usize];
        match t.kind {
            KIND_INT | KIND_STRUCT | KIND_UNION | KIND_ENUM | KIND_ENUM64 | KIND_FLOAT => {
                Some(t.size_or_type)
            }
            // BTF doesn't record pointer width; the loader runs on the same
            // architecture as the kernel.
            KIND_PTR => Some(std::mem::size_of::<usize>() as u32),
            KIND_ARRAY => {
                let elem = u32_at(&self.data, t.extra).ok()?;
                let nelems = u32_at(&self.data, t.extra + 8).ok()?;
                Some(self.size_of(elem)? * nelems)
            }
            _ => None,
        }
    }

    fn struct_id(&self, name: &str) -> Result<u32> {
        self.types
            .iter()
            .position(|t| t.kind == KIND_STRUCT && t.vlen > 0 && self.name(t.name_off) == name)
            .map(|i| i as u32)
            .with_context(|| format!("struct {name} not found in kernel BTF"))
    }

    /// Whether there is a function named `name`.
    pub fn has_func(&self, name: &str) -> bool {
        self.func_params(name).is_some()
    }

    /// Number of parameters of the function named `name`.
    pub fn func_params(&self, name: &str) -> Option<u32> {
        let func = self
            .types
            .iter()
            .find(|t| t.kind == KIND_FUNC && self.name(t.name_off) == name)?;
        let proto = self.types.get(func.size_or_type as usize)?;
        (proto.kind == KIND_FUNC_PROTO).then_some(proto.vlen)
    }

    /// Find `member` in `struct struct_name`, descending into anonymous
    /// structs and unions.
    pub fn member(&self, struct_name: &str, member: &str) -> Result<Member> {
        let id = self.struct_id(struct_name)?;
        let (bit_offset, type_id) = self
            .find_member(id, member, 0)?
            .with_context(|| format!("member {struct_name}.{member} not found"))?;
        if bit_offset % 8 != 0 {
            bail!("{struct_name}.{member} is not byte aligned");
        }
        let size = self
            .size_of(type_id)
            .with_context(|| format!("can't size {struct_name}.{member}"))?;
        Ok(Member {
            offset: bit_offset / 8,
            size,
        })
    }

    fn find_member(&self, id: u32, member: &str, base_bits: u32) -> Result<Option<(u32, u32)>> {
        let t = self.types[self.resolve(id) as usize];
        if t.kind != KIND_STRUCT && t.kind != KIND_UNION {
            return Ok(None);
        }
        for i in 0..t.vlen as usize {
            let m = t.extra + 12 * i;
            let name_off = u32_at(&self.data, m)?;
            let type_id = u32_at(&self.data, m + 4)?;
            let raw_offset = u32_at(&self.data, m + 8)?;
            let (bit_offset, bitfield_size) = if t.kind_flag {
                (raw_offset & 0xff_ffff, raw_offset >> 24)
            } else {
                (raw_offset, 0)
            };
            let name = self.name(name_off);
            if name == member {
                if bitfield_size != 0 {
                    bail!("{member} is a bitfield");
                }
                return Ok(Some((base_bits + bit_offset, type_id)));
            }
            if name.is_empty() {
                if let Some(found) = self.find_member(type_id, member, base_bits + bit_offset)? {
                    return Ok(Some(found));
                }
            }
        }
        Ok(None)
    }
}

fn u32_at(data: &[u8], pos: usize) -> Result<u32> {
    let bytes = data.get(pos..pos + 4).context("BTF read out of bounds")?;
    Ok(u32::from_ne_bytes(bytes.try_into().unwrap()))
}
