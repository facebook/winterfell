// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::{are_equal, EvaluationResult};
use core::slice;
use winterfell::{
    crypto::{Digest, Hasher},
    math::{fields::f128::BaseElement, FieldElement},
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

/// Function state is set to 6 field elements or 96 bytes; 4 elements are reserved for rate
/// and 2 elements are reserved for capacity.
pub const STATE_WIDTH: usize = 6;
pub const RATE_WIDTH: usize = 4;

/// Two elements (32-bytes) are returned as digest.
const DIGEST_SIZE: usize = 2;

/// The number of rounds is set to 7 to provide 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
/// security margin here differs from Rescue Prime specification which suggests 50% security
/// margin (and would require 8 rounds) primarily to make AIR a bit simpler.
pub const NUM_ROUNDS: usize = 7;

/// Minimum cycle length required to describe Rescue permutation.
pub const CYCLE_LENGTH: usize = 8;

// TYPES AND INTERFACES
// ================================================================================================

pub struct Rescue128 {
    state: [BaseElement; STATE_WIDTH],
    idx: usize,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct Hash([BaseElement; DIGEST_SIZE]);

// RESCUE128 IMPLEMENTATION
// ================================================================================================

impl Rescue128 {
    /// Returns a new hasher with the state initialized to all zeros.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Rescue128 {
            state: [BaseElement::ZERO; STATE_WIDTH],
            idx: 0,
        }
    }

    /// Absorbs data into the hasher state.
    pub fn update(&mut self, data: &[BaseElement]) {
        for &element in data {
            self.state[self.idx] += element;
            self.idx += 1;
            if self.idx % RATE_WIDTH == 0 {
                apply_permutation(&mut self.state);
                self.idx = 0;
            }
        }
    }

    /// Returns hash of the data absorbed into the hasher.
    pub fn finalize(mut self) -> Hash {
        if self.idx > 0 {
            // TODO: apply proper padding
            apply_permutation(&mut self.state);
        }
        Hash([self.state[0], self.state[1]])
    }

    /// Returns hash of the provided data.
    pub fn digest(data: &[BaseElement]) -> Hash {
        // initialize state to all zeros
        let mut state = [BaseElement::ZERO; STATE_WIDTH];

        let mut i = 0;
        for &element in data.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        if i > 0 {
            // TODO: apply proper padding
            apply_permutation(&mut state);
        }

        Hash([state[0], state[1]])
    }
}

// HASHER IMPLEMENTATION
// ================================================================================================

impl Hasher for Rescue128 {
    type Digest = Hash;

    const COLLISION_RESISTANCE: u32 = 64;

    fn hash(_bytes: &[u8]) -> Self::Digest {
        unimplemented!("not implemented")
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::digest(Hash::hashes_as_elements(values))
    }

    fn merge_with_int(_seed: Self::Digest, _value: u64) -> Self::Digest {
        unimplemented!("not implemented")
    }
}

// HASH IMPLEMENTATION
// ================================================================================================

impl Hash {
    pub fn new(v1: BaseElement, v2: BaseElement) -> Self {
        Hash([v1, v2])
    }

    #[allow(dead_code)]
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&self.0[0].to_bytes());
        bytes[16..].copy_from_slice(&self.0[1].to_bytes());
        bytes
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_elements(&self) -> [BaseElement; DIGEST_SIZE] {
        self.0
    }

    pub fn hashes_as_elements(hashes: &[Hash]) -> &[BaseElement] {
        let p = hashes.as_ptr();
        let len = hashes.len() * DIGEST_SIZE;
        unsafe { slice::from_raw_parts(p as *const BaseElement, len) }
    }
}

impl Digest for Hash {
    fn as_bytes(&self) -> [u8; 32] {
        let bytes = BaseElement::elements_as_bytes(&self.0);
        let mut result = [0; 32];
        result[..bytes.len()].copy_from_slice(bytes);
        result
    }
}

impl Serializable for Hash {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.0[0]);
        target.write(self.0[1]);
    }
}

impl Deserializable for Hash {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = BaseElement::read_from(source)?;
        let v2 = BaseElement::read_from(source)?;
        Ok(Self([v1, v2]))
    }
}

// RESCUE PERMUTATION
// ================================================================================================

/// Applies Rescue-XLIX permutation to the provided state.
pub fn apply_permutation(state: &mut [BaseElement; STATE_WIDTH]) {
    // apply round function 7 times; this provides 128-bit security with 40% security margin
    for i in 0..NUM_ROUNDS {
        apply_round(state, i);
    }
}

/// Rescue-XLIX round function;
/// implementation based on algorithm 3 from <https://eprint.iacr.org/2020/1143.pdf>
#[inline(always)]
pub fn apply_round(state: &mut [BaseElement], step: usize) {
    // determine which round constants to use
    let ark = ARK[step % CYCLE_LENGTH];

    // apply first half of Rescue round
    apply_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[i];
    }

    // apply second half of Rescue round
    apply_inv_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[STATE_WIDTH + i];
    }
}

// CONSTRAINTS
// ================================================================================================

/// when flag = 1, enforces constraints for a single round of Rescue hash functions
pub fn enforce_round<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    flag: E,
) {
    // compute the state that should result from applying the first half of Rescue round
    // to the current state of the computation
    let mut step1 = [E::ZERO; STATE_WIDTH];
    step1.copy_from_slice(current);
    apply_sbox(&mut step1);
    apply_mds(&mut step1);
    for i in 0..STATE_WIDTH {
        step1[i] += ark[i];
    }

    // compute the state that should result from applying the inverse for the second
    // half for Rescue round to the next step of the computation
    let mut step2 = [E::ZERO; STATE_WIDTH];
    step2.copy_from_slice(next);
    for i in 0..STATE_WIDTH {
        step2[i] -= ark[STATE_WIDTH + i];
    }
    apply_inv_mds(&mut step2);
    apply_sbox(&mut step2);

    // make sure that the results are equal
    for i in 0..STATE_WIDTH {
        result.agg_constraint(i, flag, are_equal(step2[i], step1[i]));
    }
}

// ROUND CONSTANTS
// ================================================================================================

/// Returns Rescue round constants arranged in column-major form.
pub fn get_round_constants() -> Vec<Vec<BaseElement>> {
    let mut constants = Vec::new();
    for _ in 0..(STATE_WIDTH * 2) {
        constants.push(vec![BaseElement::ZERO; CYCLE_LENGTH]);
    }

    #[allow(clippy::needless_range_loop)]
    for i in 0..CYCLE_LENGTH {
        for j in 0..(STATE_WIDTH * 2) {
            constants[j][i] = ARK[i][j];
        }
    }

    constants
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
#[allow(clippy::needless_range_loop)]
fn apply_sbox<E: FieldElement>(state: &mut [E]) {
    for i in 0..STATE_WIDTH {
        state[i] = state[i].exp(ALPHA.into());
    }
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
fn apply_inv_sbox(state: &mut [BaseElement]) {
    for i in 0..STATE_WIDTH {
        state[i] = state[i].exp(INV_ALPHA);
    }
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
fn apply_mds<E: FieldElement + From<BaseElement>>(state: &mut [E]) {
    let mut result = [E::ZERO; STATE_WIDTH];
    let mut temp = [E::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            temp[j] = E::from(MDS[i * STATE_WIDTH + j]) * state[j];
        }

        for j in 0..STATE_WIDTH {
            result[i] += temp[j];
        }
    }
    state.copy_from_slice(&result);
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
fn apply_inv_mds<E: FieldElement + From<BaseElement>>(state: &mut [E]) {
    let mut result = [E::ZERO; STATE_WIDTH];
    let mut temp = [E::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            temp[j] = E::from(INV_MDS[i * STATE_WIDTH + j]) * state[j];
        }

        for j in 0..STATE_WIDTH {
            result[i] += temp[j];
        }
    }
    state.copy_from_slice(&result);
}

// CONSTANTS
// ================================================================================================

/// S-Box and Inverse S-Box powers;
/// computed using algorithm 6 from <https://eprint.iacr.org/2020/1143.pdf>
const ALPHA: u32 = 5;
const INV_ALPHA: u128 = 272225893536750770770699646362995969229;

/// Rescue MDS matrix
/// Computed using algorithm 4 from <https://eprint.iacr.org/2020/1143.pdf>
const MDS: [BaseElement; STATE_WIDTH * STATE_WIDTH] = [
    BaseElement::new(340282366920938463463374557953730612630),
    BaseElement::new(21493836),
    BaseElement::new(340282366920938463463374557953736934518),
    BaseElement::new(914760),
    BaseElement::new(340282366920938463463374557953744928504),
    BaseElement::new(364),
    BaseElement::new(340282366920938463463374557948521959389),
    BaseElement::new(7809407397),
    BaseElement::new(340282366920938463463374557950844620457),
    BaseElement::new(324945621),
    BaseElement::new(340282366920938463463374557953733852285),
    BaseElement::new(99463),
    BaseElement::new(340282366920938463463374556526559624596),
    BaseElement::new(2132618407920),
    BaseElement::new(340282366920938463463374557163162978137),
    BaseElement::new(88084432800),
    BaseElement::new(340282366920938463463374557950784345879),
    BaseElement::new(25095280),
    BaseElement::new(340282366920938463463374197863906102577),
    BaseElement::new(537966647357139),
    BaseElement::new(340282366920938463463374358646073999137),
    BaseElement::new(22165576349400),
    BaseElement::new(340282366920938463463374557212857010097),
    BaseElement::new(6174066262),
    BaseElement::new(340282366920938463463285966851139685903),
    BaseElement::new(132344277849702072),
    BaseElement::new(340282366920938463463325536573199985698),
    BaseElement::new(5448481182864720),
    BaseElement::new(340282366920938463463374376171390478291),
    BaseElement::new(1506472167928),
    BaseElement::new(340282366920938463441758328918057706841),
    BaseElement::new(32291274613403616174),
    BaseElement::new(340282366920938463451414421516665416977),
    BaseElement::new(1329039099788841441),
    BaseElement::new(340282366920938463463330243139804660633),
    BaseElement::new(366573514642546),
];

const INV_MDS: [BaseElement; STATE_WIDTH * STATE_WIDTH] = [
    BaseElement::new(133202720344903784697302507504318451498),
    BaseElement::new(9109562341901685402869515497167051415),
    BaseElement::new(187114562320006661061623258692072377978),
    BaseElement::new(217977550980311337650875125151512141987),
    BaseElement::new(274535269264332978809051716514493438195),
    BaseElement::new(198907435511358942768401550501671423539),
    BaseElement::new(107211340690419935719675873160429442610),
    BaseElement::new(93035459208639798096019355873148696692),
    BaseElement::new(34612840942819361370119536876515785819),
    BaseElement::new(28124271099756519590702162721340502811),
    BaseElement::new(220883180661145883341796932300840696133),
    BaseElement::new(196697641239095428808435254975214799010),
    BaseElement::new(48198755643822249649260269442324041679),
    BaseElement::new(64419499747985404280993270855996080557),
    BaseElement::new(280207800449835933431237404716657540948),
    BaseElement::new(61755931245950637038951462642746253929),
    BaseElement::new(206737575380416523686108693210925354496),
    BaseElement::new(19245171373866178840198015038840651466),
    BaseElement::new(133290479635000282395391929030461304726),
    BaseElement::new(256035933367497105928763702353648605000),
    BaseElement::new(97077987470620839632334052346344687963),
    BaseElement::new(144638736603246051821344039641662500876),
    BaseElement::new(323753713558453221824969500168839490204),
    BaseElement::new(66050250127997888787320450320278295843),
    BaseElement::new(107416947271017171483976049725783774207),
    BaseElement::new(29799978553141132526384006297614595309),
    BaseElement::new(112991183841517485419461727429810868869),
    BaseElement::new(27096959906733835564333321118624482460),
    BaseElement::new(197262955506413467422574209301409294301),
    BaseElement::new(205996708763053834510019802034246907929),
    BaseElement::new(114827794598835201662537916675749328586),
    BaseElement::new(22232541983454090535685600849896663137),
    BaseElement::new(84718265936029339288536427868493390350),
    BaseElement::new(176534200716138685131361645691447579493),
    BaseElement::new(304590074876810806644622682832255680729),
    BaseElement::new(317944222651547267127379399943392242317),
];

/// Rescue round constants;
/// computed using algorithm 5 from <https://eprint.iacr.org/2020/1143.pdf>
pub const ARK: [[BaseElement; STATE_WIDTH * 2]; CYCLE_LENGTH] = [
    [
        BaseElement::new(232350694689151131917165570858777669544),
        BaseElement::new(297138716840883070166239111380460167036),
        BaseElement::new(262280230220923724082396709497064092149),
        BaseElement::new(172158049344191113832187131208632037738),
        BaseElement::new(49064466045797039562408393043269857959),
        BaseElement::new(310779117230843293557874990285120450495),
        BaseElement::new(256706820970445617734149759518940865107),
        BaseElement::new(79123538858040670180278455836284339197),
        BaseElement::new(78750303544367952484014721485273250812),
        BaseElement::new(288861383492149579433903883762711410179),
        BaseElement::new(59801749333456280387477464033868461625),
        BaseElement::new(21443300235508431203706748477819269958),
    ],
    [
        BaseElement::new(58568963110264836729315799795504150465),
        BaseElement::new(330748576252425315826992430477036516321),
        BaseElement::new(186265990460580587588657915966473647991),
        BaseElement::new(33474186560709631768594728335471560699),
        BaseElement::new(158848462530608412921046130349797355353),
        BaseElement::new(103951280788776493556470655637893338265),
        BaseElement::new(143328281743837680325887693977200434046),
        BaseElement::new(84141533915622931968833899936597847300),
        BaseElement::new(8289043147167319381038668861607412243),
        BaseElement::new(182690551456641207603161012621368395791),
        BaseElement::new(189966993584382842241685332212477020587),
        BaseElement::new(32137923394454105763485467845755642950),
    ],
    [
        BaseElement::new(37831789571282423629213813309051107559),
        BaseElement::new(128553631204082467137622394929811125529),
        BaseElement::new(267986778741944677472811189878493395927),
        BaseElement::new(16604948458564067211433039503683613987),
        BaseElement::new(336102510949899388907937615764984494068),
        BaseElement::new(269515689098362827313089599343791905108),
        BaseElement::new(299424679105391259942771484229152481303),
        BaseElement::new(204910193356347483970850685012209050540),
        BaseElement::new(297547986861132400067173315704469727918),
        BaseElement::new(90994669428470088728996184833134573519),
        BaseElement::new(194832530917116381832912394976136685925),
        BaseElement::new(3544879195102182108390682435201981399),
    ],
    [
        BaseElement::new(339480205126523778084089852053600037139),
        BaseElement::new(7584482258985997923597941079175892345),
        BaseElement::new(293411952222390873312400094181647328549),
        BaseElement::new(199529004542042321671242096609546451065),
        BaseElement::new(67129123347758775813781826519244753478),
        BaseElement::new(262358775581253675478636059962684988488),
        BaseElement::new(214578730175648891816936630380713062555),
        BaseElement::new(298888476681892954783673663609236117055),
        BaseElement::new(28713802418311531156758766332916445632),
        BaseElement::new(1440134829402109711440873134882900954),
        BaseElement::new(136568912729847804743104940208565395935),
        BaseElement::new(282333114631262903665175684297593586626),
    ],
    [
        BaseElement::new(179980515973143677823617972256218090691),
        BaseElement::new(262324617228293661450608983002445445851),
        BaseElement::new(101457408539557988072857167265007764003),
        BaseElement::new(135015365700146217343913438445165565670),
        BaseElement::new(160037359781136723784361845515476884821),
        BaseElement::new(182530253870899012049936279038476084254),
        BaseElement::new(135879876810809726132885131537021449499),
        BaseElement::new(232021530889024386996643355214152586646),
        BaseElement::new(145764181560102807472161589832442506602),
        BaseElement::new(30096323905520593555387863391076216460),
        BaseElement::new(26964230850883304384940372063347292502),
        BaseElement::new(248723932438838238159920468579438468564),
    ],
    [
        BaseElement::new(294269904099379916907622037481357861347),
        BaseElement::new(68547751515194812125080398554316505804),
        BaseElement::new(206967528806115588933607920597265054243),
        BaseElement::new(218563991130423186053843420486943196637),
        BaseElement::new(271753381570791699387473121354016967661),
        BaseElement::new(280821616954361601859332610476339898658),
        BaseElement::new(10004341245328361103806488533574675264),
        BaseElement::new(102737972201824925757345477497905200949),
        BaseElement::new(181579715086871199454198713448655357907),
        BaseElement::new(334443686013848360201749831728546200670),
        BaseElement::new(43930702221243327593116820380585481596),
        BaseElement::new(16744004758332429127464852702179311517),
    ],
    [
        BaseElement::new(310201738135125726809998762242791360596),
        BaseElement::new(155126893730515639579436939964032992002),
        BaseElement::new(61238650483248463229462616021804212788),
        BaseElement::new(6693212157784826508674787451860949238),
        BaseElement::new(197651057967963974372308220503477603713),
        BaseElement::new(174221476673212934077040088950046690415),
        BaseElement::new(287511813733819668564695051918836002922),
        BaseElement::new(304531189544765525159398110881793396421),
        BaseElement::new(276777415462914862553995344360435589651),
        BaseElement::new(241036817921529641113885285343669990717),
        BaseElement::new(320958231309550951576801366383624382828),
        BaseElement::new(242260690344880997681123448650535822378),
    ],
    [
        BaseElement::new(201589105262974747061391276271612166799),
        BaseElement::new(21009766855942890883171267876432289297),
        BaseElement::new(303226336248222109074995022589884483065),
        BaseElement::new(105515432862530091605210357969101266504),
        BaseElement::new(235097661610089805414814372959229370626),
        BaseElement::new(210361497167001742816223425802317150493),
        BaseElement::new(218546747003262668455051521918398855294),
        BaseElement::new(280724473534270362895764829061545243190),
        BaseElement::new(179926408118748249708833901850481685351),
        BaseElement::new(168859451670725335987760025077648496937),
        BaseElement::new(127174659756870191527945451601624140498),
        BaseElement::new(290826558340641225374953827677533570165),
    ],
];
