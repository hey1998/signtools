#include <windows.h>
#include <process.h>
#include <commctrl.h>
#include "resource.h"

extern ret;
extern char result[];
void __cdecl start_address(void * ignored);

HINSTANCE g_hInstance;
HWND m_curwnd;
char szFilter[]="Android Package\0*.apk\0All\0*.*\0";
char szFile0[]="your_app_signed.apk";
char szOpen[MAX_PATH];
char szSave[MAX_PATH];

char* windows[] = {
  MAKEINTRESOURCE(IDD_INFO),
  MAKEINTRESOURCE(IDD_DIR),
  MAKEINTRESOURCE(IDD_INFO),
};

BOOL CALLBACK GenericProc(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
	  SendMessage(GetDlgItem(hwndDlg, IDC_INTROTEXT),WM_SETFONT,0,MAKELPARAM(TRUE,0));
    break;
  case WM_COMMAND:
    switch (LOWORD(wParam)) {
    OPENFILENAME ofn;
    case IDC_BROWSE:
      ZeroMemory(&ofn, sizeof(ofn));
      ofn.lStructSize = sizeof(ofn);
      ofn.hwndOwner = hwndDlg;
      ofn.lpstrFile = szOpen;
      ofn.nMaxFile = sizeof(szOpen)/sizeof(*szOpen);
      ofn.lpstrFilter = szFilter;
      ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_READONLY;
      if (GetOpenFileName(&ofn) && szSave[0] == '\0') {
        int x;
        memcpy(szSave, szOpen, sizeof(szSave));
        for(x = MAX_PATH; szOpen[x] != '\\'; --x);
        x++;
        if(x + sizeof(szFile0) < sizeof(szSave))
          memcpy(&szSave[x], szFile0, sizeof(szFile0));
      }
      SetWindowText(GetDlgItem(hwndDlg, IDC_EDIT1), szOpen);
      SetWindowText(GetDlgItem(hwndDlg, IDC_EDIT2), szSave);
      break;
    case IDC_CHANGE:
      ZeroMemory(&ofn, sizeof(ofn));
      ofn.lStructSize = sizeof(ofn);
      ofn.hwndOwner = hwndDlg;
      ofn.lpstrFile = szSave;
      ofn.nMaxFile = sizeof(szSave)/sizeof(*szSave);
      ofn.lpstrFilter = szFilter;
      ofn.lpstrDefExt = "apk";
      ofn.Flags = OFN_SHOWHELP | OFN_OVERWRITEPROMPT;
      GetSaveFileName(&ofn);
      SetWindowText(GetDlgItem(hwndDlg, IDC_EDIT2), szSave);
      break;
    case IDOK:
      SetWindowText(GetDlgItem(hwndDlg, IDC_TEXT1), result);
      break;
    }
    break;
  }
  return 0;
}

BOOL CALLBACK DialogProc(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam) {
  static int i = -1;
	switch (uMsg) {
	case WM_INITDIALOG:
		ShowWindow(GetDlgItem(hwndDlg, IDC_CHILDRECT), SW_SHOW);
    SendMessage(hwndDlg, WM_COMMAND, MAKEWORD(IDOK, 0), 0);
    SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(g_hInstance, MAKEINTRESOURCE(IDR_MAINFRAME)));
		ShowWindow(hwndDlg, SW_SHOW);
		break;
	case WM_COMMAND:
    switch (LOWORD(wParam)) {
    case IDOK:
    case IDC_BACK:
      i+=(LOWORD(wParam)==IDOK)?1:-1;
      if (i < 0) {
        i = 0;
        break;
      }
      if (i >= (int)sizeof(windows)/sizeof(char*)) {
        i = sizeof(windows)/sizeof(char*) - 1;
        break;
      }
      if (m_curwnd) DestroyWindow(m_curwnd);
      m_curwnd=CreateDialog(g_hInstance,windows[i],hwndDlg,GenericProc);
      switch (i) {
        case 0:
          ShowWindow(GetDlgItem(hwndDlg, IDC_BACK), SW_HIDE);
          break;
        case sizeof(windows)/sizeof(char*) - 1:
          if(szOpen[0] == '\0' || szSave[0] == '\0') {
            SendMessage(hwndDlg, WM_COMMAND, MAKEWORD(IDC_BACK, 0), 0);
            goto err;
          }
          SetWindowText(GetDlgItem(m_curwnd, IDC_TEXT1), NULL);
          ShowWindow(GetDlgItem(hwndDlg, IDC_BACK), SW_HIDE);
          ShowWindow(GetDlgItem(hwndDlg, IDOK), SW_HIDE);
          _beginthread(start_address, 0, NULL);
          break;
        case 1:
          SetWindowText(GetDlgItem(m_curwnd, IDC_EDIT1), szOpen);
          SetWindowText(GetDlgItem(m_curwnd, IDC_EDIT2), szSave);
        default:
          ShowWindow(GetDlgItem(hwndDlg, IDOK), SW_SHOW);
          ShowWindow(GetDlgItem(hwndDlg, IDC_BACK), SW_SHOW);
          break;
      }
      if (m_curwnd)
      {
        RECT r;
        GetWindowRect(GetDlgItem(hwndDlg,IDC_CHILDRECT),&r);
        ScreenToClient(hwndDlg,(LPPOINT)&r);
        SetWindowPos(m_curwnd,0,r.left,r.top,0,0,SWP_NOACTIVATE|SWP_NOSIZE|SWP_NOZORDER);
        ShowWindow(m_curwnd,SW_SHOWNA);
      }
      break;
    default:
      if(!ret)
        EndDialog(hwndDlg, 0);
      break;
    }
    break;
	}
err:
	return 0;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
  InitCommonControls();
  g_hInstance = hInstance;
	DialogBox(
		g_hInstance,
		MAKEINTRESOURCE(IDD_INST),
		0,
		DialogProc
	);
	return 0;
}
