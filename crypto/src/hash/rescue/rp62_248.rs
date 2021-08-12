// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{exp_acc, ElementDigest, Hasher};
use core::convert::TryInto;
use math::{fields::f62::BaseElement, FieldElement};

// CONSTANTS
// ================================================================================================

const DIGEST_SIZE: usize = 4;
const STATE_WIDTH: usize = 12;
const NUM_ROUNDS: usize = 7;

//const ALPHA: u32 = 3;
//const INV_ALPHA: u64 = 3074416663688030891;

const CYCLE_LENGTH: usize = 8;

// HASHER IMPLEMENTATION
// ================================================================================================

pub struct Rp62_248();

impl Hasher for Rp62_248 {
    type Digest = ElementDigest<BaseElement, DIGEST_SIZE>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // TODO: implement properly
        let mut state = [BaseElement::default(); STATE_WIDTH];
        state[0] = BaseElement::new(bytes[0] as u64);

        apply_permutation(&mut state);
        ElementDigest(state[..4].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [BaseElement::default(); STATE_WIDTH];
        state[..4].copy_from_slice(&values[0].0);
        state[4..8].copy_from_slice(&values[1].0);

        apply_permutation(&mut state);
        ElementDigest(state[..4].try_into().unwrap())
    }

    fn merge_with_int(_seed: Self::Digest, _value: u64) -> Self::Digest {
        unimplemented!()
    }
}

// RESCUE PERMUTATION
// ================================================================================================

/// Applies Rescue-XLIX permutation to the provided state.
fn apply_permutation(state: &mut [BaseElement; STATE_WIDTH]) {
    // apply round function 7 times; this provides 128-bit security with 40% security margin
    for i in 0..NUM_ROUNDS {
        apply_round(state, i);
    }
}

/// Rescue-XLIX round function;
/// implementation based on algorithm 3 from <https://eprint.iacr.org/2020/1143.pdf>
#[inline(always)]
fn apply_round(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
    // apply first half of Rescue round
    apply_sbox(state);
    apply_mds(state);
    state.iter_mut().zip(ARK1[round]).for_each(|(s, k)| *s += k);

    // apply second half of Rescue round
    apply_inv_sbox(state);
    apply_mds(state);
    state.iter_mut().zip(ARK2[round]).for_each(|(s, k)| *s += k);
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn apply_mds(state: &mut [BaseElement; STATE_WIDTH]) {
    let mut result = [BaseElement::ZERO; STATE_WIDTH];
    result.iter_mut().zip(MDS).for_each(|(r, mds_row)| {
        state.iter().zip(mds_row).for_each(|(&s, m)| {
            *r += m * s;
        });
    });
    *state = result
}

#[inline(always)]
fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| *v = v.cube())
}

#[inline(always)]
fn apply_inv_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    // compute base^3074416663688030891 using 69 multiplications per array element
    // 3074416663688030891 = b10101010101010100001011010101010101010101010101010101010101011

    // compute base^10
    let mut t1 = *state;
    t1.iter_mut().for_each(|t1| *t1 = t1.square());

    // compute base^1010
    let t2 = exp_acc::<BaseElement, STATE_WIDTH, 2>(t1, t1);

    // compute base^10101010
    let t4 = exp_acc::<BaseElement, STATE_WIDTH, 4>(t2, t2);

    // compute base^1010101010101010
    let t8 = exp_acc::<BaseElement, STATE_WIDTH, 8>(t4, t4);

    // compute base^10101010101010100001010
    let acc = exp_acc::<BaseElement, STATE_WIDTH, 7>(t8, t2);

    // compute base^10101010101010100001011010101010101010
    let acc = exp_acc::<BaseElement, STATE_WIDTH, 15>(acc, t8);

    // compute base^101010101010101000010110101010101010101010101010101010
    let acc = exp_acc::<BaseElement, STATE_WIDTH, 16>(acc, t8);

    // compute base^10101010101010100001011010101010101010101010101010101010101010
    let acc = exp_acc::<BaseElement, STATE_WIDTH, 8>(acc, t4);

    // compute base^10101010101010100001011010101010101010101010101010101010101011
    state.iter_mut().zip(acc).for_each(|(s, a)| *s *= a);
}

// MDS
// ================================================================================================

const MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = [
    [
        BaseElement::new(3950144678237376122),
        BaseElement::new(2690153189131774333),
        BaseElement::new(936645784682382348),
        BaseElement::new(3107191214132265415),
        BaseElement::new(2603209838230440664),
        BaseElement::new(1199396433148647196),
        BaseElement::new(1282983482067326228),
        BaseElement::new(461437407589395643),
        BaseElement::new(2214977176974126410),
        BaseElement::new(360795585898440),
        BaseElement::new(4611624977880333167),
        BaseElement::new(265720),
    ],
    [
        BaseElement::new(3536793164176604955),
        BaseElement::new(1911503332938627860),
        BaseElement::new(3418675122760523340),
        BaseElement::new(1504989930332511353),
        BaseElement::new(2722575982003138843),
        BaseElement::new(1431609872573058051),
        BaseElement::new(1192456656548488631),
        BaseElement::new(545546930229576032),
        BaseElement::new(945223199513254881),
        BaseElement::new(1241455355734630133),
        BaseElement::new(4607295377894412377),
        BaseElement::new(52955405230),
    ],
    [
        BaseElement::new(4170851182034451356),
        BaseElement::new(4049722115827050441),
        BaseElement::new(2592958603203603955),
        BaseElement::new(1591126261909367400),
        BaseElement::new(1258275846807863107),
        BaseElement::new(1998950167196902314),
        BaseElement::new(3042201191319512244),
        BaseElement::new(543039388605157758),
        BaseElement::new(1398996793391337371),
        BaseElement::new(4366181202594792993),
        BaseElement::new(2647705527662157444),
        BaseElement::new(9741692640081640),
    ],
    [
        BaseElement::new(2734904247639408359),
        BaseElement::new(4279587509601476247),
        BaseElement::new(4485482368008952587),
        BaseElement::new(3891839128198288856),
        BaseElement::new(3605615068318190226),
        BaseElement::new(4481033712623965820),
        BaseElement::new(4511906145686918697),
        BaseElement::new(3379942354449020806),
        BaseElement::new(3990599459674901680),
        BaseElement::new(3930378924631282611),
        BaseElement::new(2736309679810514295),
        BaseElement::new(4088651356677543187),
    ],
    [
        BaseElement::new(842258110397353220),
        BaseElement::new(3379876823114508085),
        BaseElement::new(1075495666387844288),
        BaseElement::new(2308322198399190449),
        BaseElement::new(535073101119307124),
        BaseElement::new(2549013922555968548),
        BaseElement::new(2089967165864721761),
        BaseElement::new(1833259538539094178),
        BaseElement::new(1286299364399671252),
        BaseElement::new(3116429868056012525),
        BaseElement::new(3765145590440791140),
        BaseElement::new(276983628385769116),
    ],
    [
        BaseElement::new(1299560456850023050),
        BaseElement::new(4414989737001639740),
        BaseElement::new(627780834867342283),
        BaseElement::new(1711770898052004155),
        BaseElement::new(1979604523493335895),
        BaseElement::new(33488920757262988),
        BaseElement::new(3296083413419576217),
        BaseElement::new(716111559512999319),
        BaseElement::new(1748727787185165915),
        BaseElement::new(2725007460252215875),
        BaseElement::new(2185047820717910109),
        BaseElement::new(2319951565550756140),
    ],
    [
        BaseElement::new(4184625686841861769),
        BaseElement::new(1784981074793151883),
        BaseElement::new(502457291852703062),
        BaseElement::new(345570060311611630),
        BaseElement::new(2471821400707240604),
        BaseElement::new(2133038110899525730),
        BaseElement::new(939120245208093777),
        BaseElement::new(4151312447988641414),
        BaseElement::new(210626922136569504),
        BaseElement::new(2121768124528492214),
        BaseElement::new(3469035391047007665),
        BaseElement::new(743768221345332434),
    ],
    [
        BaseElement::new(2145694559473526100),
        BaseElement::new(1632268183143575659),
        BaseElement::new(440280249850363795),
        BaseElement::new(1074260737240252344),
        BaseElement::new(434235372443698697),
        BaseElement::new(4579079558834190297),
        BaseElement::new(507988595809300562),
        BaseElement::new(746255436130103157),
        BaseElement::new(1959107915115263608),
        BaseElement::new(4030330146733953284),
        BaseElement::new(3748621471482452510),
        BaseElement::new(1760002751403551673),
    ],
    [
        BaseElement::new(2299194066166806303),
        BaseElement::new(2406031288159683129),
        BaseElement::new(3724303300393675060),
        BaseElement::new(3136303930848425791),
        BaseElement::new(842217609243732235),
        BaseElement::new(2433222065782096659),
        BaseElement::new(1853915347332186193),
        BaseElement::new(3565339054535487990),
        BaseElement::new(3159752035320462032),
        BaseElement::new(1001592926358592140),
        BaseElement::new(1070575826169209928),
        BaseElement::new(2177302522881920563),
    ],
    [
        BaseElement::new(2207526749486243134),
        BaseElement::new(4032720262691072240),
        BaseElement::new(1260214313840482146),
        BaseElement::new(3621152551536391331),
        BaseElement::new(1609693674346558276),
        BaseElement::new(1076797379868177960),
        BaseElement::new(1050224695423079188),
        BaseElement::new(1679887683779537233),
        BaseElement::new(1053394941293588429),
        BaseElement::new(2176319632402176708),
        BaseElement::new(807051555764923088),
        BaseElement::new(2483141537228001953),
    ],
    [
        BaseElement::new(873986056056007361),
        BaseElement::new(2985158312969304104),
        BaseElement::new(2082576071668149043),
        BaseElement::new(1607709264834493266),
        BaseElement::new(1027130385873843589),
        BaseElement::new(3876861839368848637),
        BaseElement::new(2999813843878199730),
        BaseElement::new(3252530728916107838),
        BaseElement::new(4464640832314938694),
        BaseElement::new(1978539358398864357),
        BaseElement::new(3425590232595452442),
        BaseElement::new(3706838041850115299),
    ],
    [
        BaseElement::new(3407508207732360664),
        BaseElement::new(2899952415584588394),
        BaseElement::new(282047285293952955),
        BaseElement::new(4147714396995528527),
        BaseElement::new(1141786266584343815),
        BaseElement::new(3523991864183271024),
        BaseElement::new(1659008334442446407),
        BaseElement::new(2857663046861472404),
        BaseElement::new(1954265424153359502),
        BaseElement::new(4018750979872307732),
        BaseElement::new(494911809436924696),
        BaseElement::new(1282149942051721903),
    ],
];

// ROUND CONSTANTS
// ================================================================================================
pub const ARK1: [[BaseElement; STATE_WIDTH]; CYCLE_LENGTH] = [
    [
        BaseElement::new(2066114551762569441),
        BaseElement::new(3806895469920197238),
        BaseElement::new(4101271467144175579),
        BaseElement::new(597783788093439290),
        BaseElement::new(3459529549731874958),
        BaseElement::new(3361732357449281221),
        BaseElement::new(4510044102131299796),
        BaseElement::new(2674251637583411151),
        BaseElement::new(4589456981709905074),
        BaseElement::new(97204927704726530),
        BaseElement::new(3366467278170867590),
        BaseElement::new(1661995649761352250),
    ],
    [
        BaseElement::new(2552080730515318124),
        BaseElement::new(4551129269607279176),
        BaseElement::new(3896238353185798118),
        BaseElement::new(4378451547412130464),
        BaseElement::new(1120678946404787820),
        BaseElement::new(3392815550656692052),
        BaseElement::new(3397267446269039551),
        BaseElement::new(2148161493216445570),
        BaseElement::new(449851947043698998),
        BaseElement::new(2745778316253333994),
        BaseElement::new(3247100729373266485),
        BaseElement::new(1474512661374883327),
    ],
    [
        BaseElement::new(3875405236566248698),
        BaseElement::new(3509172052827303011),
        BaseElement::new(232674088014396347),
        BaseElement::new(4189609763147780999),
        BaseElement::new(3106901133683704323),
        BaseElement::new(592695797873090171),
        BaseElement::new(266738566669046215),
        BaseElement::new(2668509039085882180),
        BaseElement::new(950720373611234910),
        BaseElement::new(1192091586747406812),
        BaseElement::new(2245360993531047612),
        BaseElement::new(2031514636218081872),
    ],
    [
        BaseElement::new(2291456653144584105),
        BaseElement::new(869259464485808552),
        BaseElement::new(1154055231930493301),
        BaseElement::new(1843073679205946182),
        BaseElement::new(1748748883129851856),
        BaseElement::new(4085632850766581010),
        BaseElement::new(2907511654177734852),
        BaseElement::new(1563252740420931271),
        BaseElement::new(57166044462862224),
        BaseElement::new(3237323403752048612),
        BaseElement::new(4563484427236835576),
        BaseElement::new(2956709587309713553),
    ],
    [
        BaseElement::new(2157779262561212790),
        BaseElement::new(2452020513593893218),
        BaseElement::new(3051597722203497560),
        BaseElement::new(3131962147511514023),
        BaseElement::new(194930663253195526),
        BaseElement::new(930794074695110797),
        BaseElement::new(3616451697350340387),
        BaseElement::new(1493869649774878568),
        BaseElement::new(2790579710588613698),
        BaseElement::new(4552593272704308029),
        BaseElement::new(931863165972727433),
        BaseElement::new(2628222466499909093),
    ],
    [
        BaseElement::new(628982718083809865),
        BaseElement::new(3809487906119235546),
        BaseElement::new(1412055838972795717),
        BaseElement::new(2702758340764464061),
        BaseElement::new(643165380746471120),
        BaseElement::new(1755475976486779630),
        BaseElement::new(4322584783908582556),
        BaseElement::new(2377752666356883186),
        BaseElement::new(3806838324704149861),
        BaseElement::new(3978620600887524391),
        BaseElement::new(2546609133879704944),
        BaseElement::new(3704323050566652251),
    ],
    [
        BaseElement::new(364418616620607840),
        BaseElement::new(557500673241722848),
        BaseElement::new(2838167312179774894),
        BaseElement::new(919171238566781484),
        BaseElement::new(1810286722734245651),
        BaseElement::new(2647811277753845608),
        BaseElement::new(1083073358474695843),
        BaseElement::new(2087740333294235353),
        BaseElement::new(3237593972479805167),
        BaseElement::new(2979012086287276314),
        BaseElement::new(4247318354894968843),
        BaseElement::new(4339035876293932168),
    ],
    [
        BaseElement::new(637464443586979476),
        BaseElement::new(2836759567512989604),
        BaseElement::new(2810771120313048804),
        BaseElement::new(933847926071662702),
        BaseElement::new(3671300003323773082),
        BaseElement::new(1302583912073804613),
        BaseElement::new(1599597190376846885),
        BaseElement::new(3744381265009855087),
        BaseElement::new(2639095668805356140),
        BaseElement::new(1001607423519830780),
        BaseElement::new(2649493298619816104),
        BaseElement::new(497568504817846927),
    ],
];

pub const ARK2: [[BaseElement; STATE_WIDTH]; CYCLE_LENGTH] = [
    [
        BaseElement::new(3819036781602939606),
        BaseElement::new(887046499825451011),
        BaseElement::new(2129644207518417092),
        BaseElement::new(2927054444958183703),
        BaseElement::new(3938394192009721127),
        BaseElement::new(4350492790583122386),
        BaseElement::new(3932489874389553135),
        BaseElement::new(2187735113981662094),
        BaseElement::new(2707268329521558754),
        BaseElement::new(1672475830798880457),
        BaseElement::new(577661991381759440),
        BaseElement::new(4202413457369478629),
    ],
    [
        BaseElement::new(2386138289504492057),
        BaseElement::new(3614836749985123032),
        BaseElement::new(1959364639655691456),
        BaseElement::new(3952161783467742979),
        BaseElement::new(2113797503569123694),
        BaseElement::new(2706761515468719677),
        BaseElement::new(1408899580454624727),
        BaseElement::new(1752562999883762712),
        BaseElement::new(2699036399761024947),
        BaseElement::new(2111974313315470120),
        BaseElement::new(1945634303007041433),
        BaseElement::new(603680138767490486),
    ],
    [
        BaseElement::new(216541366065294490),
        BaseElement::new(1663917238463860974),
        BaseElement::new(3681161841551456227),
        BaseElement::new(1463044976083347872),
        BaseElement::new(4293067359825676566),
        BaseElement::new(3701547299239100959),
        BaseElement::new(2198012560927400476),
        BaseElement::new(924090339017537873),
        BaseElement::new(4592565695695653575),
        BaseElement::new(2568652539159558382),
        BaseElement::new(2556673802560280889),
        BaseElement::new(2055200673419696274),
    ],
    [
        BaseElement::new(675825972975288687),
        BaseElement::new(157304917963529210),
        BaseElement::new(2874195676109427150),
        BaseElement::new(400733584567227315),
        BaseElement::new(982698402204661622),
        BaseElement::new(820183842893732317),
        BaseElement::new(301881572013037058),
        BaseElement::new(1963857632534980766),
        BaseElement::new(4091993061963419897),
        BaseElement::new(4102179200035343013),
        BaseElement::new(886874507443125118),
        BaseElement::new(1900379595653484868),
    ],
    [
        BaseElement::new(663951223276314056),
        BaseElement::new(3247862347650141921),
        BaseElement::new(2405853211128575753),
        BaseElement::new(2313821214725089833),
        BaseElement::new(892865509580640652),
        BaseElement::new(3786801988137677226),
        BaseElement::new(1708051655041482785),
        BaseElement::new(413367975786665969),
        BaseElement::new(4184177931828745920),
        BaseElement::new(1902978742415691889),
        BaseElement::new(3457684352259258126),
        BaseElement::new(2092600929857819767),
    ],
    [
        BaseElement::new(3616150808336931771),
        BaseElement::new(3206846600545625539),
        BaseElement::new(3830153390371624940),
        BaseElement::new(2654199900015314333),
        BaseElement::new(783490214003335242),
        BaseElement::new(3730076606034436027),
        BaseElement::new(3784919641869206369),
        BaseElement::new(2204748845493012644),
        BaseElement::new(448185939031874189),
        BaseElement::new(435945873799083567),
        BaseElement::new(695310862494154666),
        BaseElement::new(2112586212508747422),
    ],
    [
        BaseElement::new(1802926915815728451),
        BaseElement::new(2057340163436909216),
        BaseElement::new(982232855844273391),
        BaseElement::new(1559347186127685318),
        BaseElement::new(1420221884912541505),
        BaseElement::new(4213862187371016442),
        BaseElement::new(476828620219460093),
        BaseElement::new(4518037022029400598),
        BaseElement::new(186346377116487094),
        BaseElement::new(4479404873270208061),
        BaseElement::new(3269764362972891817),
        BaseElement::new(2929967273325723272),
    ],
    [
        BaseElement::new(1555175681720018923),
        BaseElement::new(2913517096498256645),
        BaseElement::new(2119225001993504406),
        BaseElement::new(1383803580992220774),
        BaseElement::new(4395189003224844853),
        BaseElement::new(248814153532786695),
        BaseElement::new(3675667117284746347),
        BaseElement::new(1077282323180186121),
        BaseElement::new(2847878069549966282),
        BaseElement::new(1830325602477655465),
        BaseElement::new(3241765544416225076),
        BaseElement::new(3803032785619635880),
    ],
];

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::{BaseElement, FieldElement, STATE_WIDTH};

    #[test]
    fn test_inv_sbox() {
        const INV_ALPHA: u64 = 3074416663688030891;

        let state: [BaseElement; STATE_WIDTH] = [
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
            BaseElement::rand(),
        ];

        let mut expected = state;
        expected.iter_mut().for_each(|v| *v = v.exp(INV_ALPHA));

        let mut actual = state;
        super::apply_inv_sbox(&mut actual);

        assert_eq!(expected, actual);
    }
}
