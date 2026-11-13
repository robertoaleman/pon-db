// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
//
// Tabla hash estática por páginas (revisión 4).
//
// El índice guarda hashes con clave (uniformes) y las consultas solo piden igualdad, así que el
// orden no sirve de nada: la tabla se direcciona. La página "natural" de un hash es
// `⌊hash · buckets / 2^64⌋`. Cada página admite 255 entradas; si la natural está llena, la entrada
// pasa a la página siguiente (sondeo lineal por páginas). Como el archivo se escribe una sola vez,
// la cota del sondeo (`max_probe`) se mide al construir y queda escrita en la cabecera autenticada:
// buscar una clave lee como mucho `max_probe` páginas, un número independiente del tamaño del archivo.
use crate::v9::header::PAGE_ENTRIES;
use std::io;

/// Página natural de un hash. Es monótona: con hashes crecientes, páginas no decrecientes.
pub fn natural_page(hash: u64, buckets: usize) -> usize {
    (((hash as u128) * (buckets as u128)) >> 64) as usize
}

/// Páginas de direccionamiento para `entries` entradas con una carga objetivo del 75 %:
/// `⌈entries / (255 · 0.75)⌉`.
pub fn bucket_count_for(entries: usize) -> usize {
    (entries * 4 + 764) / 765
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceStats {
    /// Páginas escritas: las de direccionamiento más las que añade el desborde del final.
    pub page_count: usize,
    /// Páginas que hay que leer, como máximo, para decidir si una clave está.
    pub max_probe: usize,
}

/// Coloca las entradas (ORDENADAS por hash, punteros distintos de 0) y llama a `emit` una vez por
/// cada página, en orden y sin saltos, incluidas las vacías.
///
/// Regla de búsqueda que esta colocación garantiza: para un hash con página natural `p`, se lee `p`,
/// `p+1`, ... hasta encontrarlo o hasta una página con menos de 255 entradas (ahí termina la cadena).
pub fn place_pages<F>(entries: &[(u64, u64)], buckets: usize, mut emit: F) -> io::Result<PlaceStats>
where
    F: FnMut(usize, &[(u64, u64)]) -> io::Result<()>,
{
    let mut cur: usize = 0;
    let mut page: Vec<(u64, u64)> = Vec::with_capacity(PAGE_ENTRIES);
    let mut max_probe: usize = 1;

    for &(hash, ptr) in entries {
        let natural = natural_page(hash, buckets);
        if natural > cur {
            // saltar a su página natural: se cierran la actual y las vacías intermedias
            emit(cur, &page)?;
            for empty in cur + 1..natural {
                emit(empty, &[])?;
            }
            page.clear();
            cur = natural;
        }
        if page.len() == PAGE_ENTRIES {
            // la página está llena: la entrada desborda a la siguiente
            emit(cur, &page)?;
            page.clear();
            cur += 1;
        }
        page.push((hash, ptr));
        max_probe = max_probe.max(cur - natural + 1);
    }

    emit(cur, &page)?;
    let mut page_count = cur + 1;
    while page_count < buckets {
        emit(page_count, &[])?;
        page_count += 1;
    }
    Ok(PlaceStats { page_count, max_probe })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Búsqueda con la misma regla que el lector.
    fn find(pages: &[Vec<(u64, u64)>], buckets: usize, max_probe: usize, hash: u64) -> Option<u64> {
        let natural = natural_page(hash, buckets);
        for i in 0..max_probe {
            let p = natural + i;
            if p >= pages.len() {
                break;
            }
            for &(h, ptr) in &pages[p] {
                if h == hash {
                    return Some(ptr);
                }
            }
            if pages[p].len() < PAGE_ENTRIES {
                return None;
            }
        }
        None
    }

    fn place(entries: &[(u64, u64)], buckets: usize) -> (Vec<Vec<(u64, u64)>>, PlaceStats) {
        let mut pages: Vec<Vec<(u64, u64)>> = Vec::new();
        let stats = place_pages(entries, buckets, |no, page| {
            assert_eq!(no, pages.len(), "pages must be emitted in order, none skipped");
            pages.push(page.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(pages.len(), stats.page_count);
        (pages, stats)
    }

    /// Hashes pseudoaleatorios, distintos y ordenados (generador congruencial; no necesita `rand`).
    fn sorted_hashes(n: usize, seed: u64) -> Vec<u64> {
        let mut x = seed;
        let mut v: Vec<u64> = (0..n)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                x ^ (x >> 29)
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    #[test]
    fn natural_page_is_monotonic_and_in_range() {
        for buckets in [1usize, 2, 7, 1000, 1_000_003] {
            assert_eq!(natural_page(0, buckets), 0);
            assert_eq!(natural_page(u64::MAX, buckets), buckets - 1);
            let mut last = 0;
            for h in sorted_hashes(5000, 3) {
                let p = natural_page(h, buckets);
                assert!(p < buckets && p >= last);
                last = p;
            }
        }
    }

    #[test]
    fn bucket_count_targets_a_75_percent_load() {
        assert_eq!(bucket_count_for(1), 1);
        assert_eq!(bucket_count_for(191), 1);
        assert_eq!(bucket_count_for(192), 2);
        assert_eq!(bucket_count_for(1_000_000), 5_229);
    }

    #[test]
    fn uniform_hashes_are_all_found_within_a_small_probe() {
        let hashes = sorted_hashes(30_000, 11);
        let entries: Vec<(u64, u64)> = hashes.iter().enumerate().map(|(i, &h)| (h, i as u64 + 1)).collect();
        let buckets = bucket_count_for(entries.len());
        let (pages, stats) = place(&entries, buckets);

        assert!(stats.max_probe <= 3, "max_probe = {}", stats.max_probe);
        assert!(stats.page_count >= buckets);
        assert!(pages.iter().all(|p| p.len() <= PAGE_ENTRIES));
        assert_eq!(pages.iter().map(|p| p.len()).sum::<usize>(), entries.len());

        for &(h, ptr) in &entries {
            assert_eq!(find(&pages, buckets, stats.max_probe, h), Some(ptr));
        }
        for absent in sorted_hashes(3000, 99) {
            if hashes.binary_search(&absent).is_err() {
                assert_eq!(find(&pages, buckets, stats.max_probe, absent), None);
            }
        }
    }

    #[test]
    fn overflow_spills_to_the_next_pages_and_the_probe_bound_covers_it() {
        // 700 entradas con la misma página natural (0): 255 + 255 + 190
        let entries: Vec<(u64, u64)> = (0..700u64).map(|i| ((i + 1) * 1000, i + 1)).collect();
        let (pages, stats) = place(&entries, 100);

        assert_eq!(stats.page_count, 100);
        assert_eq!(stats.max_probe, 3);
        assert_eq!([pages[0].len(), pages[1].len(), pages[2].len(), pages[3].len()], [255, 255, 190, 0]);
        for &(h, ptr) in &entries {
            assert_eq!(find(&pages, 100, stats.max_probe, h), Some(ptr));
        }
        // una clave ausente con la misma página natural termina en la primera página no llena
        assert_eq!(find(&pages, 100, stats.max_probe, 1234), None);
    }

    #[test]
    fn overflow_after_the_last_bucket_adds_pages() {
        // 300 entradas cuya página natural es la última (1 de 2)
        let entries: Vec<(u64, u64)> = (0..300u64).map(|i| ((1u64 << 63) + (i + 1) * 1000, i + 1)).collect();
        let (pages, stats) = place(&entries, 2);

        assert_eq!(stats.page_count, 3, "one page beyond the addressing space");
        assert_eq!(stats.max_probe, 2);
        assert_eq!([pages[0].len(), pages[1].len(), pages[2].len()], [0, 255, 45]);
        for &(h, ptr) in &entries {
            assert_eq!(find(&pages, 2, stats.max_probe, h), Some(ptr));
        }
    }

    #[test]
    fn untouched_pages_are_still_emitted_in_order() {
        let entries = vec![((u64::MAX / 10) * 5 + 7, 1u64)]; // página natural 5 de 10
        let (pages, stats) = place(&entries, 10);
        assert_eq!(stats, PlaceStats { page_count: 10, max_probe: 1 });
        assert_eq!(pages.iter().map(|p| p.len()).collect::<Vec<_>>(), vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
    }
}
