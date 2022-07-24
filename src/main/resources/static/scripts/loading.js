const aes256Service = () => {
  /* 로딩바 보이기 */
  const showLoading = () => {
    document.getElementById('loading').style.display = 'flex';
    document.getElementById('btn_signup').disabled = true;
  }

  /* 로딩바 감추기 */
  const hideLoading = () => {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('btn_signup').disabled = false;
  }
  return {
    showLoading: showLoading,
    hideLoading: hideLoading
  }
}