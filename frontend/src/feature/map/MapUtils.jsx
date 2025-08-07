export const createInfoWindowContent = (
  facility,
  categoryColors,
  reviewInfo,
) => {
  const detailUrl =
    `/facility/${encodeURIComponent(facility.name)}` +
    (facility.id ? `?id=${facility.id}` : "") +
    `&sido=${encodeURIComponent(facility.sidoName || "")}` +
    `&sigungu=${encodeURIComponent(facility.sigunguName || "")}`;

  let badgesHtml = "";

  if (facility.category2 && categoryColors[facility.category2]) {
    const category2Color = categoryColors[facility.category2];
    badgesHtml += `<span class="badge ms-1" style="background-color:${category2Color}; font-size: 8px;">${facility.category2}</span>`;
  }

  if (facility.category3 && categoryColors[facility.category3]) {
    const category3Color = categoryColors[facility.category3];
    badgesHtml += `<span class="badge ms-1" style="background-color:${category3Color}; font-size: 8px;">${facility.category3}</span>`;
  }

  let reviewHtml = `
    <p class="mb-1 small" style="color: #888;">
      리뷰 정보 불러오는 중...
    </p>
  `;

  if (reviewInfo && reviewInfo.reviewCount > 0) {
    reviewHtml = `
      <p class="mb-1 small">
        ⭐ <strong>${reviewInfo.averageRating}</strong> / 5점 (${reviewInfo.reviewCount}개)
      </p>
    `;
  }

  return `
    <div style="font-size: 11px; border: none;">
      <div class="card-body p-1">
        <h6 class="card-title mb-1" style="font-size: 12px; font-weight: bold;">
          ${facility.name || "이름 없음"}
          ${badgesHtml} 
        </h6>
        
        ${reviewHtml}

        <p class="mb-1 small text-secondary">📍 ${facility.roadAddress || facility.jibunAddress || "주소 정보 없음"}</p>
        ${facility.phoneNumber ? `<p class="text-primary mb-1 small">📞 ${facility.phoneNumber}</p>` : ""}
        ${facility.allowedPetSize ? `<p class="text-success mb-1 small">🐕 ${facility.allowedPetSize}</p>` : ""}
        ${facility.parkingAvailable === "Y" ? `<p class="text-info mb-1 small">🅿️ 주차가능</p>` : ""}
        ${facility.holiday ? `<p class="text-muted mb-1 small">🗓️ 휴무: ${facility.holiday}</p>` : ""}
        ${facility.operatingHours ? `<p class="text-muted mb-1 small">⏰ ${facility.operatingHours}</p>` : ""}
        ${facility.petRestrictions ? `<p class="text-warning mb-1 small">🚫 ${facility.petRestrictions}</p>` : ""}
      </div>
      <a href="${detailUrl}">상세보기</a>
    </div>
  `;
};
