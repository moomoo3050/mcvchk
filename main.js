async function DNSquery(domain, type) {
    try {
        const response = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=${type}`, {
            headers: { "accept": "application/dns-json" }
        });

        const resp = await response.json();

        if (resp.Answer && resp.Answer.length > 0) {
            return resp.Answer[0].data;
        } else {
            throw new Error("NXDOMAIN");
        }
    } catch (error) {
        console.error(error, domain, type); 
    }
}
//디버깅용 놔둘지 말지 고민중
function getParams () {
    const urlParams = new URLSearchParams(window.location.search);

    if (urlParams.has("domain")) {
        document.querySelector("#sv-addr").value = urlParams.get("domain");
    }

    if (urlParams.has("ip")) {
        document.querySelector("#ip").value = urlParams.get("ip");
    }
}

async function getIPaddr(){
    await fetch('https://api.ipify.org?format=json')
    .then(response=>response.json())
    .then(data=>{
        document.querySelector("#ip").value = data.ip;
    }); 
}

function safe(element) {
    element.style.color = "green";
    element.style.backgroundColor = "honeydew";
    element.title = "IP주소가 검출되지 않았습니다.";
}

function warn(element) {
    element.style.color = "orange";
    element.style.backgroundColor = "Ivory";
    element.title = "잠재적 위협이 있습니다.";
}

function danger(element) {
    element.style.color = "red";
    element.style.backgroundColor = "mistyrose"; 
    element.title = "입력한 IP주소가 노출되었습니다.";
}

async function check(){

    // 도메인 패턴
    const domainPattern = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$/;
    // IP 패턴
    const ipPattern = /^(?:25[0-5]|2[0-4]\d|1?\d\d?)\.(?:25[0-5]|2[0-4]\d|1?\d\d?)\.(?:25[0-5]|2[0-4]\d|1?\d\d?)\.(?:25[0-5]|2[0-4]\d|1?\d\d?)$/;

    // input 값 수집
    var sv_addr = document.querySelector("#sv-addr").value; // 서버 주소(mcv.kr 제외)
    var ip_addr = document.querySelector("#ip").value; //ip 주소
    var service = document.querySelector("#service").options[document.querySelector("#service").selectedIndex].text;

    // 입력 값 확인인
    if (sv_addr == "" || ip_addr == ""){
        alert("값을 입력해주세요.");
        return;
    }

    if (!ipPattern.test(ip_addr)) {
        alert("유효한 IPv4 주소를 입력하세요.");
        document.querySelector("#ip").value = "";
        document.querySelector("#ip").focus();
        return;
    }

    if (!domainPattern.test(sv_addr+".mcv.kr")) {
        alert("유효한 서버 주소를 입력하세요.");
        document.querySelector("#sv-addr").value = "";
        document.querySelector("#sv-addr").focus();
        return;
    }

    // 결과 표시 오브젝트 초기화
    
    const A = document.querySelector("#A")
    const SRV = document.querySelector("#SRV")
    const MCV = document.querySelector("#MCV")

    
    //미리 쿼리 값 불러오기
    const A_record = await DNSquery(`${sv_addr}.mcv.kr`, "A"); 
    const SRV_record = (await this.DNSquery(`_${service}._tcp.${sv_addr}.mcv.kr`, "SRV")).split(" "); //아니 정상적으로 받았는데 왜 undefined가 뜨는거야
    const SRV_A_record = await DNSquery(SRV_record.at(-1), "A");
    
    // 결과 표시 
    /*
    todo: 에러났을 경우 통과 되지 않도록 수정 필요
    */
    if (A_record == ip_addr){ // A 레코드 확인
        A.textContent = "위험"// A 레코드와 IP 주소가 일치할 경우 위험
        danger(A);
    } else if (ipPattern.test(A_record)) { // A 레코드가 IP 주소인 경우
        A.textContent = `다른 IP 주소 검출(${A_record})`;
        warn(A);
    } else {
        A.textContent = "발견되지 않음";
        safe(A);
    }   

    if (SRV_record[-1] == ip_addr){ // SRV 레코드 확인
        SRV.textContent = "위험" // SRV 레코드와 IP 주소가 일치할 경우 위험
        danger(SRV);
    } else if (ipPattern.test(SRV_record.at(-1))) { // SRV 레코드가 IP 주소인 경우
        SRV.textContent = `다른 IP 주소 검출(${SRV_record.at(-1)})`;  
        warn(SRV);  
    } else {
        SRV.textContent = "발견되지 않음";
        safe(SRV);
    }

    if (!domainPattern.test(SRV_A_record)) { // SRV 레코드의 A레코드가 도메인 이 아닐경우
        if (SRV_A_record == ip_addr) { // SRV 레코드의 A 레코드와 IP 주소가 일치할 경우
                MCV.textContent = "위험" //위험
                danger(MCV);
        } else if (ipPattern.test(SRV_A_record)) { // SRV 레코드의 A 레코드가 IP 주소인 경우 
                MCV.textContent = `다른 ip 주소 검출(${SRV_A_record})` //잠재적 위험(ip주소 검출)
                warn(MCV);
        } else { //도메인 주소 인 경우 mcv.kr인지 확인인
            if (SRV_A_record == "pipefilter.mcv.kr.") {
                MCV.setAttribute('style', 'white-space: pre;');
                MCV.textContent = `mcv.kr pipefilter 서비스 연결됨\r\n(보안주소: ${SRV_record.at(-1)}:${SRV_record.at(-2)})` //포트(pipefilter 서비스 id)
                safe(MCV);
            } else {
                MCV.textContent = "pipefilter서비스에 연결되지 않음";
                warn(MCV);
            }
        }
    }
}