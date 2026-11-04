// URL detection for X's weighted post length, ported from twitter-text 3.1.0 (extractUrlsWithIndices and
// the regular expressions and IDNA check it uses), so that a URL is found, and counted as 23, exactly
// where X's own counter finds one: with or without http(s)://, and ending before CJK text, an emoji or
// trailing punctuation that follows it.
//
// twitter-text: Copyright 2018 Twitter, Inc., licensed under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0). punycode.js 2.1.0 (the version in Node, which
// twitter-text calls): Copyright Mathias Bynens, MIT License. Changes: ported to TypeScript, and the
// punycode encoder reduced to the encoded length that the IDNA check needs.
// Full copyright notices and license texts: THIRD_PARTY_NOTICES.md.

/** One URL as twitter-text reports it: the text it counts as a URL, and where that text starts (UTF-16). */
export interface UrlEntity { url: string; start: number }

const MAX_URL_LENGTH = 4096;
const MAX_TCO_SLUG_LENGTH = 40;
const MAX_DOMAIN_LABEL_LENGTH = 63;
const DEFAULT_PROTOCOL = 'https://';

// Top-level domains, in twitter-text 3.1.0's order.
const GTLDS =
  '\uC0BC\uC131|\uB2F7\uCEF4|\uB2F7\uB137|\u9999\u683C\u91CC\u62C9|\u9910\u5385|\u98DF\u54C1|' +
  '\u98DE\u5229\u6D66|\u96FB\u8A0A\u76C8\u79D1|\u96C6\u56E2|\u901A\u8CA9|\u8D2D\u7269|\u8C37\u6B4C|' +
  '\u8BFA\u57FA\u4E9A|\u8054\u901A|\u7F51\u7EDC|\u7F51\u7AD9|\u7F51\u5E97|\u7F51\u5740|' +
  '\u7EC4\u7EC7\u673A\u6784|\u79FB\u52A8|\u73E0\u5B9D|\u70B9\u770B|\u6E38\u620F|\u6DE1\u9A6C\u9521|' +
  '\u673A\u6784|\u66F8\u7C4D|\u65F6\u5C1A|\u65B0\u95FB|\u653F\u5E9C|\u653F\u52A1|\u62DB\u8058|\u624B\u8868|' +
  '\u624B\u673A|\u6211\u7231\u4F60|\u6148\u5584|\u5FAE\u535A|\u5E7F\u4E1C|\u5DE5\u884C|\u5BB6\u96FB|' +
  '\u5A31\u4E50|\u5929\u4E3B\u6559|\u5927\u62FF|\u5927\u4F17\u6C7D\u8F66|\u5728\u7EBF|' +
  '\u5609\u91CC\u5927\u9152\u5E97|\u5609\u91CC|\u5546\u6807|\u5546\u5E97|\u5546\u57CE|\u516C\u76CA|' +
  '\u516C\u53F8|\u516B\u5366|\u5065\u5EB7|\u4FE1\u606F|\u4F5B\u5C71|\u4F01\u4E1A|\u4E2D\u6587\u7F51|' +
  '\u4E2D\u4FE1|\u4E16\u754C|\u30DD\u30A4\u30F3\u30C8|\u30D5\u30A1\u30C3\u30B7\u30E7\u30F3|\u30BB\u30FC\u30EB|' +
  '\u30B9\u30C8\u30A2|\u30B3\u30E0|\u30B0\u30FC\u30B0\u30EB|\u30AF\u30E9\u30A6\u30C9|\u307F\u3093\u306A|' +
  '\u0E04\u0E2D\u0E21|\u0938\u0902\u0917\u0920\u0928|\u0928\u0947\u091F|\u0915\u0949\u092E|' +
  '\u0647\u0645\u0631\u0627\u0647|\u0645\u0648\u0642\u0639|\u0645\u0648\u0628\u0627\u064A\u0644\u064A|' +
  '\u0643\u0648\u0645|\u0643\u0627\u062B\u0648\u0644\u064A\u0643|\u0639\u0631\u0628|\u0634\u0628\u0643\u0629|' +
  '\u0628\u064A\u062A\u0643|\u0628\u0627\u0632\u0627\u0631|\u0627\u0644\u0639\u0644\u064A\u0627\u0646|' +
  '\u0627\u0631\u0627\u0645\u0643\u0648|\u0627\u062A\u0635\u0627\u0644\u0627\u062A|' +
  '\u0627\u0628\u0648\u0638\u0628\u064A|\u05E7\u05D5\u05DD|\u0441\u0430\u0439\u0442|\u0440\u0443\u0441|' +
  '\u043E\u0440\u0433|\u043E\u043D\u043B\u0430\u0439\u043D|\u043C\u043E\u0441\u043A\u0432\u0430|' +
  '\u043A\u043E\u043C|\u043A\u0430\u0442\u043E\u043B\u0438\u043A|\u0434\u0435\u0442\u0438|zuerich|zone|zippo|' +
  'zip|zero|zara|zappos|yun|youtube|you|yokohama|yoga|yodobashi|yandex|yamaxun|yahoo|yachts|xyz|xxx|xperia|xin|' +
  'xihuan|xfinity|xerox|xbox|wtf|wtc|wow|world|works|work|woodside|wolterskluwer|wme|winners|wine|windows|win|' +
  'williamhill|wiki|wien|whoswho|weir|weibo|wedding|wed|website|weber|webcam|weatherchannel|weather|watches|' +
  'watch|warman|wanggou|wang|walter|walmart|wales|vuelos|voyage|voto|voting|vote|volvo|volkswagen|vodka|' +
  'vlaanderen|vivo|viva|vistaprint|vista|vision|visa|virgin|vip|vin|villas|viking|vig|video|viajes|vet|' +
  'versicherung|verm\u00F6gensberatung|verm\u00F6gensberater|verisign|ventures|vegas|vanguard|vana|vacations|' +
  'ups|uol|uno|university|unicom|uconnect|ubs|ubank|tvs|tushu|tunes|tui|tube|trv|trust|travelersinsurance|' +
  'travelers|travelchannel|travel|training|trading|trade|toys|toyota|town|tours|total|toshiba|toray|top|tools|' +
  'tokyo|today|tmall|tkmaxx|tjx|tjmaxx|tirol|tires|tips|tiffany|tienda|tickets|tiaa|theatre|theater|thd|teva|' +
  'tennis|temasek|telefonica|telecity|tel|technology|tech|team|tdk|tci|taxi|tax|tattoo|tatar|tatamotors|target|' +
  'taobao|talk|taipei|tab|systems|symantec|sydney|swiss|swiftcover|swatch|suzuki|surgery|surf|support|supply|' +
  'supplies|sucks|style|study|studio|stream|store|storage|stockholm|stcgroup|stc|statoil|statefarm|statebank|' +
  'starhub|star|staples|stada|srt|srl|spreadbetting|spot|sport|spiegel|space|soy|sony|song|solutions|solar|' +
  'sohu|software|softbank|social|soccer|sncf|smile|smart|sling|skype|sky|skin|ski|site|singles|sina|silk|' +
  'shriram|showtime|show|shouji|shopping|shop|shoes|shiksha|shia|shell|shaw|sharp|shangrila|sfr|sexy|sex|sew|' +
  'seven|ses|services|sener|select|seek|security|secure|seat|search|scot|scor|scjohnson|science|schwarz|schule|' +
  'school|scholarships|schmidt|schaeffler|scb|sca|sbs|sbi|saxo|save|sas|sarl|sapo|sap|sanofi|sandvikcoromant|' +
  'sandvik|samsung|samsclub|salon|sale|sakura|safety|safe|saarland|ryukyu|rwe|run|ruhr|rugby|rsvp|room|rogers|' +
  'rodeo|rocks|rocher|rmit|rip|rio|ril|rightathome|ricoh|richardli|rich|rexroth|reviews|review|restaurant|rest|' +
  'republican|report|repair|rentals|rent|ren|reliance|reit|reisen|reise|rehab|redumbrella|redstone|red|recipes|' +
  'realty|realtor|realestate|read|raid|radio|racing|qvc|quest|quebec|qpon|pwc|pub|prudential|pru|protection|' +
  'property|properties|promo|progressive|prof|productions|prod|pro|prime|press|praxi|pramerica|post|porn|' +
  'politie|poker|pohl|pnc|plus|plumbing|playstation|play|place|pizza|pioneer|pink|ping|pin|pid|pictures|pictet|' +
  'pics|piaget|physio|photos|photography|photo|phone|philips|phd|pharmacy|pfizer|pet|pccw|pay|passagens|party|' +
  'parts|partners|pars|paris|panerai|panasonic|pamperedchef|page|ovh|ott|otsuka|osaka|origins|orientexpress|' +
  'organic|org|orange|oracle|open|ooo|onyourside|online|onl|ong|one|omega|ollo|oldnavy|olayangroup|olayan|' +
  'okinawa|office|off|observer|obi|nyc|ntt|nrw|nra|nowtv|nowruz|now|norton|northwesternmutual|nokia|nissay|' +
  'nissan|ninja|nikon|nike|nico|nhk|ngo|nfl|nexus|nextdirect|next|news|newholland|new|neustar|network|netflix|' +
  'netbank|net|nec|nba|navy|natura|nationwide|name|nagoya|nadex|nab|mutuelle|mutual|museum|mtr|mtpc|mtn|msd|' +
  'movistar|movie|mov|motorcycles|moto|moscow|mortgage|mormon|mopar|montblanc|monster|money|monash|mom|moi|moe|' +
  'moda|mobily|mobile|mobi|mma|mls|mlb|mitsubishi|mit|mint|mini|mil|microsoft|miami|metlife|merckmsd|meo|menu|' +
  'men|memorial|meme|melbourne|meet|media|med|mckinsey|mcdonalds|mcd|mba|mattel|maserati|marshalls|marriott|' +
  'markets|marketing|market|map|mango|management|man|makeup|maison|maif|madrid|macys|luxury|luxe|lupin|' +
  'lundbeck|ltda|ltd|lplfinancial|lpl|love|lotto|lotte|london|lol|loft|locus|locker|loans|loan|llp|llc|lixil|' +
  'living|live|lipsy|link|linde|lincoln|limo|limited|lilly|like|lighting|lifestyle|lifeinsurance|life|lidl|' +
  'liaison|lgbt|lexus|lego|legal|lefrak|leclerc|lease|lds|lawyer|law|latrobe|latino|lat|lasalle|lanxess|' +
  'landrover|land|lancome|lancia|lancaster|lamer|lamborghini|ladbrokes|lacaixa|kyoto|kuokgroup|kred|krd|kpn|' +
  'kpmg|kosher|komatsu|koeln|kiwi|kitchen|kindle|kinder|kim|kia|kfh|kerryproperties|kerrylogistics|kerryhotels|' +
  'kddi|kaufen|juniper|juegos|jprs|jpmorgan|joy|jot|joburg|jobs|jnj|jmp|jll|jlc|jio|jewelry|jetzt|jeep|jcp|jcb|' +
  'java|jaguar|iwc|iveco|itv|itau|istanbul|ist|ismaili|iselect|irish|ipiranga|investments|intuit|international|' +
  'intel|int|insure|insurance|institute|ink|ing|info|infiniti|industries|inc|immobilien|immo|imdb|imamat|ikano|' +
  'iinet|ifm|ieee|icu|ice|icbc|ibm|hyundai|hyatt|hughes|htc|hsbc|how|house|hotmail|hotels|hoteles|hot|hosting|' +
  'host|hospital|horse|honeywell|honda|homesense|homes|homegoods|homedepot|holiday|holdings|hockey|hkt|hiv|' +
  'hitachi|hisamitsu|hiphop|hgtv|hermes|here|helsinki|help|healthcare|health|hdfcbank|hdfc|hbo|haus|hangout|' +
  'hamburg|hair|guru|guitars|guide|guge|gucci|guardian|group|grocery|gripe|green|gratis|graphics|grainger|gov|' +
  'got|gop|google|goog|goodyear|goodhands|goo|golf|goldpoint|gold|godaddy|gmx|gmo|gmbh|gmail|globo|global|gle|' +
  'glass|glade|giving|gives|gifts|gift|ggee|george|genting|gent|gea|gdn|gbiz|gay|garden|gap|games|game|gallup|' +
  'gallo|gallery|gal|fyi|futbol|furniture|fund|fun|fujixerox|fujitsu|ftr|frontier|frontdoor|frogans|frl|' +
  'fresenius|free|fox|foundation|forum|forsale|forex|ford|football|foodnetwork|food|foo|fly|flsmidth|flowers|' +
  'florist|flir|flights|flickr|fitness|fit|fishing|fish|firmdale|firestone|fire|financial|finance|final|film|' +
  'fido|fidelity|fiat|ferrero|ferrari|feedback|fedex|fast|fashion|farmers|farm|fans|fan|family|faith|fairwinds|' +
  'fail|fage|extraspace|express|exposed|expert|exchange|everbank|events|eus|eurovision|etisalat|esurance|' +
  'estate|esq|erni|ericsson|equipment|epson|epost|enterprises|engineering|engineer|energy|emerck|email|' +
  'education|edu|edeka|eco|eat|earth|dvr|dvag|durban|dupont|duns|dunlop|duck|dubai|dtv|drive|download|dot|' +
  'doosan|domains|doha|dog|dodge|doctor|docs|dnp|diy|dish|discover|discount|directory|direct|digital|diet|' +
  'diamonds|dhl|dev|design|desi|dentist|dental|democrat|delta|deloitte|dell|delivery|degree|deals|dealer|deal|' +
  'dds|dclk|day|datsun|dating|date|data|dance|dad|dabur|cyou|cymru|cuisinella|csc|cruises|cruise|crs|crown|' +
  'cricket|creditunion|creditcard|credit|cpa|courses|coupons|coupon|country|corsica|coop|cool|cookingchannel|' +
  'cooking|contractors|contact|consulting|construction|condos|comsec|computer|compare|company|community|' +
  'commbank|comcast|com|cologne|college|coffee|codes|coach|clubmed|club|cloud|clothing|clinique|clinic|click|' +
  'cleaning|claims|cityeats|city|citic|citi|citadel|cisco|circle|cipriani|church|chrysler|chrome|christmas|' +
  'chloe|chintai|cheap|chat|chase|charity|channel|chanel|cfd|cfa|cern|ceo|center|ceb|cbs|cbre|cbn|cba|catholic|' +
  'catering|cat|casino|cash|caseih|case|casa|cartier|cars|careers|career|care|cards|caravan|car|capitalone|' +
  'capital|capetown|canon|cancerresearch|camp|camera|cam|calvinklein|call|cal|cafe|cab|bzh|buzz|buy|business|' +
  'builders|build|bugatti|budapest|brussels|brother|broker|broadway|bridgestone|bradesco|box|boutique|bot|' +
  'boston|bostik|bosch|boots|booking|book|boo|bond|bom|bofa|boehringer|boats|bnpparibas|bnl|bmw|bms|blue|' +
  'bloomberg|blog|blockbuster|blanco|blackfriday|black|biz|bio|bingo|bing|bike|bid|bible|bharti|bet|bestbuy|' +
  'best|berlin|bentley|beer|beauty|beats|bcn|bcg|bbva|bbt|bbc|bayern|bauhaus|basketball|baseball|bargains|' +
  'barefoot|barclays|barclaycard|barcelona|bar|bank|band|bananarepublic|banamex|baidu|baby|azure|axa|aws|' +
  'avianca|autos|auto|author|auspost|audio|audible|audi|auction|attorney|athleta|associates|asia|asda|arte|art|' +
  'arpa|army|archi|aramco|arab|aquarelle|apple|app|apartments|aol|anz|anquan|android|analytics|amsterdam|amica|' +
  'amfam|amex|americanfamily|americanexpress|alstom|alsace|ally|allstate|allfinanz|alipay|alibaba|alfaromeo|' +
  'akdn|airtel|airforce|airbus|aigo|aig|agency|agakhan|africa|afl|afamilycompany|aetna|aero|aeg|adult|ads|adac|' +
  'actor|active|aco|accountants|accountant|accenture|academy|abudhabi|abogado|able|abc|abbvie|abbott|abb|' +
  'abarth|aarp|aaa|onion';
const CCTLDS =
  '\uD55C\uAD6D|\u9999\u6E2F|\u6FB3\u9580|\u65B0\u52A0\u5761|\u53F0\u7063|\u53F0\u6E7E|\u4E2D\u570B|' +
  '\u4E2D\u56FD|\u10D2\u10D4|\u0EA5\u0EB2\u0EA7|\u0E44\u0E17\u0E22|\u0DBD\u0D82\u0D9A\u0DCF|' +
  '\u0D2D\u0D3E\u0D30\u0D24\u0D02|\u0CAD\u0CBE\u0CB0\u0CA4|\u0C2D\u0C3E\u0C30\u0C24\u0C4D|' +
  '\u0B9A\u0BBF\u0B99\u0BCD\u0B95\u0BAA\u0BCD\u0BAA\u0BC2\u0BB0\u0BCD|\u0B87\u0BB2\u0B99\u0BCD\u0B95\u0BC8|' +
  '\u0B87\u0BA8\u0BCD\u0BA4\u0BBF\u0BAF\u0BBE|\u0B2D\u0B3E\u0B30\u0B24|\u0AAD\u0ABE\u0AB0\u0AA4|' +
  '\u0A2D\u0A3E\u0A30\u0A24|\u09AD\u09BE\u09F0\u09A4|\u09AD\u09BE\u09B0\u09A4|\u09AC\u09BE\u0982\u09B2\u09BE|' +
  '\u092D\u093E\u0930\u094B\u0924|\u092D\u093E\u0930\u0924\u092E\u094D|\u092D\u093E\u0930\u0924|' +
  '\u0680\u0627\u0631\u062A|\u067E\u0627\u06A9\u0633\u062A\u0627\u0646|' +
  '\u0645\u0648\u0631\u064A\u062A\u0627\u0646\u064A\u0627|\u0645\u0644\u064A\u0633\u064A\u0627|' +
  '\u0645\u0635\u0631|\u0642\u0637\u0631|\u0641\u0644\u0633\u0637\u064A\u0646|\u0639\u0645\u0627\u0646|' +
  '\u0639\u0631\u0627\u0642|\u0633\u0648\u0631\u064A\u0629|\u0633\u0648\u062F\u0627\u0646|' +
  '\u062A\u0648\u0646\u0633|\u0628\u06BE\u0627\u0631\u062A|\u0628\u0627\u0631\u062A|' +
  '\u0627\u06CC\u0631\u0627\u0646|\u0627\u0645\u0627\u0631\u0627\u062A|\u0627\u0644\u0645\u063A\u0631\u0628|' +
  '\u0627\u0644\u0633\u0639\u0648\u062F\u064A\u0629|\u0627\u0644\u062C\u0632\u0627\u0626\u0631|' +
  '\u0627\u0644\u0628\u062D\u0631\u064A\u0646|\u0627\u0644\u0627\u0631\u062F\u0646|\u0570\u0561\u0575|' +
  '\u049B\u0430\u0437|\u0443\u043A\u0440|\u0441\u0440\u0431|\u0440\u0444|\u043C\u043E\u043D|\u043C\u043A\u0434|' +
  '\u0435\u044E|\u0431\u0435\u043B|\u0431\u0433|\u03B5\u03C5|\u03B5\u03BB|zw|zm|za|yt|ye|ws|wf|vu|vn|vi|vg|ve|' +
  'vc|va|uz|uy|us|um|uk|ug|ua|tz|tw|tv|tt|tr|tp|to|tn|tm|tl|tk|tj|th|tg|tf|td|tc|sz|sy|sx|sv|su|st|ss|sr|so|sn|' +
  'sm|sl|sk|sj|si|sh|sg|se|sd|sc|sb|sa|rw|ru|rs|ro|re|qa|py|pw|pt|ps|pr|pn|pm|pl|pk|ph|pg|pf|pe|pa|om|nz|nu|nr|' +
  'np|no|nl|ni|ng|nf|ne|nc|na|mz|my|mx|mw|mv|mu|mt|ms|mr|mq|mp|mo|mn|mm|ml|mk|mh|mg|mf|me|md|mc|ma|ly|lv|lu|lt|' +
  'ls|lr|lk|li|lc|lb|la|kz|ky|kw|kr|kp|kn|km|ki|kh|kg|ke|jp|jo|jm|je|it|is|ir|iq|io|in|im|il|ie|id|hu|ht|hr|hn|' +
  'hm|hk|gy|gw|gu|gt|gs|gr|gq|gp|gn|gm|gl|gi|gh|gg|gf|ge|gd|gb|ga|fr|fo|fm|fk|fj|fi|eu|et|es|er|eh|eg|ee|ec|dz|' +
  'do|dm|dk|dj|de|cz|cy|cx|cw|cv|cu|cr|co|cn|cm|cl|ck|ci|ch|cg|cf|cd|cc|ca|bz|by|bw|bv|bt|bs|br|bq|bo|bn|bm|bl|' +
  'bj|bi|bh|bg|bf|be|bd|bb|ba|az|ax|aw|au|at|as|ar|aq|ao|an|am|al|ai|ag|af|ae|ad|ac';

// The pieces of twitter-text's URL expression, composed the same way. Like the original, the expressions
// use the i flag without u, so the character classes apply to UTF-16 code units.
const PUNCT = String.raw`\!'#%&'\(\)*\+,\\\-\.\/:;<=>\?@\[\]\^_{|}~\$`;
const SPACES = String.raw`\x09-\x0D\x20\x85\xA0\u1680\u180E\u2000-\u200A\u2028\u2029\u202F\u205F\u3000`;
const INVALID_CHARS = String.raw`\uFFFE\uFEFF\uFFFF`;
const DIRECTIONAL_MARKERS = String.raw`\u202A-\u202E\u061C\u200E\u200F\u2066\u2067\u2068\u2069`;
const LATIN_ACCENTS = String.raw`\xC0-\xD6\xD8-\xF6\xF8-\xFF\u0100-\u024F\u0253\u0254\u0256\u0257\u0259\u025B\u0263\u0268\u026F\u0272\u0289\u028B\u02BB\u0300-\u036F\u1E00-\u1EFF`;
const CYRILLIC = String.raw`\u0400-\u04FF`;

const PRECEDING = String.raw`(?:[^A-Za-z0-9@\uFF20$#\uFF03${INVALID_CHARS}]|[${DIRECTIONAL_MARKERS}]|^)`;
/** A domain character: anything but ASCII punctuation, spaces and a few invisible characters, so CJK and emoji too. */
const DOMAIN_CHAR = `[^${PUNCT}${SPACES}${INVALID_CHARS}${DIRECTIONAL_MARKERS}]`;
const SUBDOMAIN = String.raw`(?:(?:${DOMAIN_CHAR}(?:[_-]|${DOMAIN_CHAR})*)?${DOMAIN_CHAR}\.)`;
const DOMAIN_NAME = String.raw`(?:(?:${DOMAIN_CHAR}(?:-|${DOMAIN_CHAR})*)?${DOMAIN_CHAR}\.)`;
const GTLD = `(?:(?:${GTLDS})(?=[^0-9a-zA-Z@+-]|$))`;
const CCTLD = `(?:(?:${CCTLDS})(?=[^0-9a-zA-Z@+-]|$))`;
const PUNYCODE = String.raw`(?:xn--[\-0-9a-z]+)`;
const DOMAIN = `(?:${SUBDOMAIN}*${DOMAIN_NAME}(?:${GTLD}|${CCTLD}|${PUNYCODE}))`;
/** A path character: ASCII letters, digits and some punctuation, Cyrillic, and accented Latin letters. */
const PATH_CHAR = String.raw`[a-z${CYRILLIC}0-9!\*';:=\+,\.\$\/%#\[\]\-\u2013_~@\|&${LATIN_ACCENTS}]`;
const BALANCED_PARENS = String.raw`\((?:${PATH_CHAR}+|(?:${PATH_CHAR}*\(${PATH_CHAR}+\)${PATH_CHAR}*))\)`;
/** A path ends on one of these, so trailing punctuation such as . , : ; ! ? ) ' is left out. */
const PATH_END = String.raw`[\+\-a-z${CYRILLIC}0-9=_#\/${LATIN_ACCENTS}]|(?:${BALANCED_PARENS})`;
// As in twitter-text, PATH_END's alternation is not wrapped, so a path may also be balanced parentheses alone.
const PATH = String.raw`(?:(?:${PATH_CHAR}*(?:${BALANCED_PARENS}${PATH_CHAR}*)*${PATH_END})|(?:@${PATH_CHAR}+\/))`;
const QUERY_CHAR = String.raw`[a-z0-9!?\*'@\(\);:&=\+\$\/%#\[\]\-_\.,~|]`;
const QUERY_END = String.raw`[a-z0-9\-_&=#\/]`;

/** Groups: 2 the character before, 3 the URL, 4 the protocol, 5 the domain, 6 the port, 7 the path, 8 the query. */
const EXTRACT_URL = new RegExp(String.raw`((${PRECEDING})((https?:\/\/)?(${DOMAIN})(?::([0-9]+))?(\/${PATH}*)?(\?${QUERY_CHAR}*${QUERY_END})?))`, 'gi');
const TCO_URL = new RegExp(String.raw`^https?:\/\/t\.co\/([a-z0-9]+)(?:\?${QUERY_CHAR}*${QUERY_END})?`, 'i');
const ASCII_DOMAIN = new RegExp(String.raw`(?:(?:[\-a-z0-9${LATIN_ACCENTS}]+)\.)+(?:${GTLD}|${CCTLD}|${PUNYCODE})`, 'gi');
const INVALID_BEFORE_BARE_DOMAIN = /[-_.\/]$/;

/**
 * The URLs twitter-text 3.1.0 finds in the text (extractUrlsWithIndices with its defaults, so bare domains
 * such as example.com count too), in order. Like twitter-text, a URL without a protocol keeps only its
 * ASCII domain, and a t.co link is cut after its slug.
 */
export function extractUrls(text: string): UrlEntity[] {
  if (!text || !text.includes('.')) return [];
  const urls: UrlEntity[] = [];
  EXTRACT_URL.lastIndex = 0;
  for (let match = EXTRACT_URL.exec(text); match; match = EXTRACT_URL.exec(text)) {
    const [, , before, url, protocol, domain, , path] = match;
    const end = EXTRACT_URL.lastIndex;
    const start = end - url.length;
    if (!isValidUrl(url, protocol || DEFAULT_PROTOCOL, domain)) continue;
    if (protocol) {
      // A t.co link takes no path beyond its slug.
      const tco = TCO_URL.exec(url);
      if (tco && tco[1].length > MAX_TCO_SLUG_LENGTH) continue;
      urls.push({ url: tco ? tco[0] : url, start });
      continue;
    }
    if (INVALID_BEFORE_BARE_DOMAIN.test(before)) continue;
    // Without a protocol, only the ASCII domains inside the matched domain are URLs; the last one keeps the path.
    let last: UrlEntity | undefined;
    let asciiEnd = 0;
    for (const ascii of domain.match(ASCII_DOMAIN) ?? []) {
      const asciiStart = domain.indexOf(ascii, asciiEnd);
      asciiEnd = asciiStart + ascii.length;
      last = { url: ascii, start: start + asciiStart };
      urls.push(last);
    }
    if (last && path) last.url += url.slice(domain.length);
  }
  return urls;
}

// twitter-text also adds the punycode length difference of the domain here, but its toAscii returns the
// domain unchanged, so that difference is always 0 and is left out.
function isValidUrl(url: string, protocol: string, domain: string): boolean {
  return idnaValid(domain) && protocol.length + url.length <= MAX_URL_LENGTH;
}

/** twitter-text's IDNA check: a punycode-looking domain must be ASCII, and each label must encode to 1-63 characters. */
function idnaValid(domain: string): boolean {
  if (domain.startsWith('xn--') && !domain.match(ASCII_DOMAIN)) return false;
  return domain.split('.').every(label => {
    const length = punycodeToAsciiLength(label);
    return length >= 1 && length <= MAX_DOMAIN_LABEL_LENGTH;
  });
}

/** The length of punycode.toASCII(label). U+3002, U+FF0E and U+FF61 separate labels there too. */
function punycodeToAsciiLength(label: string): number {
  const parts = label.split(/[\u3002\uFF0E\uFF61]/);
  return parts.length - 1 + parts.reduce((total, part) => total + (/[^\0-\x7F]/.test(part) ? 4 + punycodeLength(part) : part.length), 0);
}

/**
 * The length of punycode.encode(input) (RFC 3492). Each code point adds at least one character, so an input
 * over 63 code points is reported as too long without encoding it; this also keeps delta far from the
 * integer overflow punycode.js throws on.
 */
function punycodeLength(input: string): number {
  const codePoints = Array.from(input, c => c.codePointAt(0)!);
  if (codePoints.length > MAX_DOMAIN_LABEL_LENGTH) return codePoints.length;
  const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700;
  const adapt = (delta: number, points: number, first: boolean) => {
    let k = 0;
    delta = first ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / points);
    for (; delta > ((BASE - T_MIN) * T_MAX) >> 1; k += BASE) delta = Math.floor(delta / (BASE - T_MIN));
    return Math.floor(k + ((BASE - T_MIN + 1) * delta) / (delta + SKEW));
  };
  const basic = codePoints.filter(c => c < 0x80).length;
  let length = basic + (basic ? 1 : 0);
  let n = 0x80, delta = 0, bias = 72, handled = basic;
  while (handled < codePoints.length) {
    const m = Math.min(...codePoints.filter(c => c >= n));
    delta += (m - n) * (handled + 1);
    n = m;
    for (const c of codePoints) {
      if (c < n) delta++;
      if (c !== n) continue;
      let q = delta;
      for (let k = BASE; ; k += BASE) {
        const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
        if (q < t) break;
        length++;
        q = Math.floor((q - t) / (BASE - t));
      }
      length++;
      bias = adapt(delta, handled + 1, handled === basic);
      delta = 0;
      handled++;
    }
    delta++;
    n++;
  }
  return length;
}
